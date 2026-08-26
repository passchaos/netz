const std = @import("std");
const mqtt = @import("mod.zig");
const redirect = @import("redirect.zig");
const runtime = @import("runtime.zig");
const websocket = @import("../websocket/mod.zig");
const websocket_runtime = websocket.runtime;
const http1_runtime = @import("../http1/mod.zig").runtime;
const vail = @import("vail");

const net = std.Io.net;
const mqtt_subprotocol = "mqtt";

pub const ClientIdentity = vail.tls.client_auth.ClientIdentity;
pub const ClientCertificateVerifier = vail.tls.auth.ClientVerifier;

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
    allowed_origins: []const []const u8,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: ListenOptions,
    ) runtime.Error!Server {
        try runtime.validateProxyPolicy(options.limits);
        return .{
            .allocator = allocator,
            .websocket_server = try .listen(
                allocator,
                io,
                bind_address,
                websocketLimits(options.limits, options.max_head_bytes),
            ),
            .limits = options.limits,
            .allowed_origins = options.allowed_origins,
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
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    pub fn acceptPending(
        self: *Server,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.PendingAcceptedClient {
        const stream = try self.websocket_server.http.listener.accept(
            self.websocket_server.http.io,
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.websocket_server.http.io);
        var proxy_metadata = try runtime.readProxyMetadata(
            self.allocator,
            self.websocket_server.http.io,
            stream,
            self.limits,
            null,
        );
        errdefer if (proxy_metadata) |*metadata| metadata.deinit();
        const http_connection = try self.websocket_server.http.acceptStream(
            stream,
        );
        stream_owned = false;
        // acceptHttpConnection owns the HTTP connection on every return path.
        var ws = try self.websocket_server.acceptHttpConnection(
            http_connection,
            .{
                .protocols = &.{mqtt_subprotocol},
                .require_subprotocol = true,
                .allowed_origins = self.allowed_origins,
            },
        );
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
        if (proxy_metadata) |metadata| {
            connection.attachProxyMetadata(metadata);
            proxy_metadata = null;
        }
        return connection.acceptPending(options);
    }

    pub fn pendingSource(self: *Server) runtime.PendingSource {
        return .{
            .context = self,
            .accept_pending = struct {
                fn call(
                    context: *anyopaque,
                    options: runtime.AcceptOptions,
                ) anyerror!runtime.PendingAcceptedClient {
                    const server: *Server = @ptrCast(@alignCast(context));
                    return server.acceptPending(options);
                }
            }.call,
        };
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        max_connections: usize,
        options: runtime.AcceptOptions,
    ) runtime.AsyncServeError!runtime.ConcurrentServeResult {
        return serveAcceptedConcurrent(
            Server,
            self,
            self.websocket_server.http.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            options,
        );
    }
};

pub const ListenOptions = struct {
    limits: runtime.Limits = .{},
    max_head_bytes: usize = 64 * 1024,
    /// Optional exact Origin allowlist for browser MQTT clients.
    allowed_origins: []const []const u8 = &.{},
};

/// MQTT-over-WebSocket listener on a Unix-domain stream socket.
pub const UnixServer = struct {
    allocator: std.mem.Allocator,
    websocket_server: websocket_runtime.UnixServer,
    limits: runtime.Limits,
    allowed_origins: []const []const u8,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ListenOptions,
    ) runtime.Error!UnixServer {
        try runtime.validateProxyPolicy(options.limits);
        if (options.limits.proxy_protocol != null or
            options.limits.proxy_v2_require_tls or
            options.limits.proxy_v2_require_client_certificate)
        {
            return error.InvalidProperty;
        }
        var websocket_limits = websocketLimits(
            options.limits,
            options.max_head_bytes,
        );
        websocket_limits.tcp_nodelay = false;
        return .{
            .allocator = allocator,
            .websocket_server = try .listen(
                allocator,
                io,
                address,
                websocket_limits,
            ),
            .limits = options.limits,
            .allowed_origins = options.allowed_origins,
        };
    }

    pub fn deinit(self: *UnixServer) void {
        self.websocket_server.deinit();
        self.* = undefined;
    }

    pub fn accept(
        self: *UnixServer,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.AcceptedClient {
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    pub fn acceptPending(
        self: *UnixServer,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.PendingAcceptedClient {
        var ws = try self.websocket_server.accept(.{
            .protocols = &.{mqtt_subprotocol},
            .require_subprotocol = true,
            .allowed_origins = self.allowed_origins,
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
        return connection.acceptPending(options);
    }

    pub fn pendingSource(self: *UnixServer) runtime.PendingSource {
        return .{
            .context = self,
            .accept_pending = struct {
                fn call(
                    context: *anyopaque,
                    options: runtime.AcceptOptions,
                ) anyerror!runtime.PendingAcceptedClient {
                    const server: *UnixServer = @ptrCast(
                        @alignCast(context),
                    );
                    return server.acceptPending(options);
                }
            }.call,
        };
    }

    /// Accept a bounded set of Unix-domain WebSocket clients and run their
    /// MQTT handlers concurrently through the same task lifecycle as WSS.
    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        max_connections: usize,
        options: runtime.AcceptOptions,
    ) runtime.AsyncServeError!runtime.ConcurrentServeResult {
        return serveAcceptedConcurrent(
            UnixServer,
            self,
            self.websocket_server.http.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            options,
        );
    }
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
    allowed_origins: []const []const u8,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) runtime.Error!TlsServer {
        try runtime.validateProxyPolicy(options.limits);
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
                    .tls_handshake_timeout = options.tls_handshake_timeout,
                    .client_auth = options.client_auth,
                    .tcp_nodelay = options.tcp_nodelay,
                },
            ),
            .limits = options.limits,
            .allowed_origins = options.allowed_origins,
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
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    pub fn acceptPending(
        self: *TlsServer,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.PendingAcceptedClient {
        const stream = try self.websocket_server.listener.accept(
            self.websocket_server.io,
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.websocket_server.io);
        var proxy_metadata = try runtime.readProxyMetadata(
            self.allocator,
            self.websocket_server.io,
            stream,
            self.limits,
            null,
        );
        errdefer if (proxy_metadata) |*metadata| metadata.deinit();
        // acceptStream owns the socket on both success and failure.
        stream_owned = false;
        var ws = try self.websocket_server.acceptStream(stream, .{
            .protocols = &.{mqtt_subprotocol},
            .require_subprotocol = true,
            .allowed_origins = self.allowed_origins,
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
        if (proxy_metadata) |metadata| {
            connection.attachProxyMetadata(metadata);
            proxy_metadata = null;
        }
        return connection.acceptPending(options);
    }

    pub fn pendingSource(self: *TlsServer) runtime.PendingSource {
        return .{
            .context = self,
            .accept_pending = struct {
                fn call(
                    context: *anyopaque,
                    options: runtime.AcceptOptions,
                ) anyerror!runtime.PendingAcceptedClient {
                    const server: *TlsServer = @ptrCast(@alignCast(context));
                    return server.acceptPending(options);
                }
            }.call,
        };
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
        return serveAcceptedConcurrent(
            TlsServer,
            self,
            self.websocket_server.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            options,
        );
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
    /// Absolute TLS handshake receive budget before the HTTP Upgrade budget.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?@import("vail").tls.client_auth.ServerPolicy = null,
    tcp_nodelay: bool = true,
    /// Optional exact Origin allowlist for browser MQTT clients.
    allowed_origins: []const []const u8 = &.{},
};

/// Shared finite accept loop for WebSocket transports that have completed the
/// MQTT CONNECT exchange. This centralizes ownership of accepted clients and
/// keeps Unix-domain and TLS serving behavior identical.
fn serveAcceptedConcurrent(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    allocator: std.mem.Allocator,
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
    const results = try allocator.alloc(?anyerror, max_connections);
    errdefer allocator.free(results);
    @memset(results, null);

    for (results) |*result| {
        var accepted = try server.accept(options);
        errdefer accepted.deinit(allocator);
        group.async(
            io,
            ServeTask(HandlerContext).run,
            .{ServeTask(HandlerContext){
                .accepted = accepted,
                .context = context,
                .handler = handler,
                .result = result,
                .allocator = allocator,
            }},
        );
    }

    try group.await(io);
    return .{ .allocator = allocator, .errors = results };
}

fn ServeTask(comptime HandlerContext: type) type {
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
        // This overload establishes cleartext WS. Requiring an explicit WSS
        // URI for identities avoids silently discarding client credentials.
        if (options.client_identity != null) {
            return error.UnsupportedScheme;
        }
        const ws = try websocket_runtime.Client.connect(
            allocator,
            io,
            address,
            websocketConnectOptions(options),
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectUnixWithConnAck(
            allocator,
            io,
            address,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUnixWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUnixAttempt(allocator, io, address, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUnixAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        if (options.client_identity != null or options.use_vail_tls) {
            return error.UnsupportedScheme;
        }
        var ws_options = websocketConnectOptions(options);
        ws_options.tcp_nodelay = false;
        const ws = try websocket_runtime.Client.connectUnix(
            allocator,
            io,
            address,
            ws_options,
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

    /// Follow MQTT 5 redirect CONNACKs across WS/WSS authorities.
    /// TLS redirects continue to derive certificate identity from each target
    /// URI through the shared WebSocket client rather than reusing the old SNI.
    pub fn connectUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        policy: redirect.Policy,
    ) runtime.Error!runtime.ConnectResult {
        if (options.mqtt.protocol != .v5) {
            return error.UnsupportedRedirectScheme;
        }
        const parsed_initial = std.Uri.parse(uri_text) catch
            return error.InvalidServerReference;
        const default_transport: redirect.Transport =
            if (std.ascii.eqlIgnoreCase(parsed_initial.scheme, "ws"))
                .websocket
            else if (std.ascii.eqlIgnoreCase(parsed_initial.scheme, "wss"))
                .websocket_tls
            else
                return error.UnsupportedRedirectScheme;
        var chain = redirect.Chain.init(allocator, policy);
        defer chain.deinit();
        var current_uri = try allocator.dupe(u8, uri_text);
        defer allocator.free(current_uri);
        try chain.recordInitial(current_uri, default_transport);

        while (true) {
            var target = try redirect.parse(
                allocator,
                current_uri,
                default_transport,
            );
            defer target.deinit();
            if (target.transport != .websocket and
                target.transport != .websocket_tls)
            {
                return error.UnsupportedRedirectScheme;
            }
            var attempt = try connectUriAttempt(
                allocator,
                io,
                target.uri,
                options,
            );
            errdefer attempt.deinit(allocator);
            if (attempt.accepted()) return attempt.requireAccepted();
            const reference = (try redirect.referenceForConnAck(
                attempt.connack.connack,
            )) orelse return error.ConnectRefused;
            var next = try chain.follow(
                current_uri,
                reference,
                attempt.connack.connack.reason_code,
            );
            defer next.deinit();
            attempt.deinit(allocator);
            const owned = try allocator.dupe(u8, next.uri);
            allocator.free(current_uri);
            current_uri = owned;
        }
    }
};

pub const ConnectOptions = struct {
    mqtt: runtime.ConnectOptions,
    host: []const u8 = "",
    target: []const u8 = "/mqtt",
    /// Optional browser Origin header.
    origin: ?[]const u8 = null,
    max_head_bytes: usize = 64 * 1024,
    tcp_nodelay: bool = true,
    tls: http1_runtime.TlsClientOptions = .{},
    /// Select vail-backed WSS even without a client certificate, enabling
    /// authenticated peer metadata, exporter and TLS KeyUpdate APIs.
    use_vail_tls: bool = false,
    /// Select the vail-backed WSS client and answer CertificateRequest.
    client_identity: ?ClientIdentity = null,
    /// Optional pin/custom trust callback for the client-identity path.
    /// Otherwise `tls.ca_bundle` or system roots verify the server and host.
    server_verifier: ?ClientCertificateVerifier = null,
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_server_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget for the vail WSS client handshake.
    tls_handshake_timeout: ?std.Io.Duration = null,
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
        .origin = options.origin,
        .protocols = &.{mqtt_subprotocol},
        .tcp_nodelay = options.tcp_nodelay,
        .limits = websocketLimits(
            options.mqtt.limits,
            options.max_head_bytes,
        ),
        .vail_tls = if (options.use_vail_tls or
            options.client_identity != null or
            options.server_verifier != null)
            .{
                .identity = options.client_identity,
                .server_verifier = options.server_verifier,
                .cipher_suites = options.cipher_suites,
                .max_server_handshake_size = options.max_server_handshake_size,
                .handshake_timeout = options.tls_handshake_timeout,
            }
        else
            null,
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

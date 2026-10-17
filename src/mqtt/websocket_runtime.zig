const std = @import("std");
const mqtt = @import("mod.zig");
const redirect = @import("redirect.zig");
const runtime = @import("runtime.zig");
const websocket = @import("../websocket/mod.zig");
const websocket_runtime = websocket.runtime;
const http1 = @import("../http1/mod.zig");
const http1_runtime = http1.runtime;
const tls_stream = @import("../tls/mod.zig").stream;
const accept_deadline = @import("../internal/accept.zig");
const deadline_policy = @import("../internal/deadline.zig");
const vail = @import("vail");

const net = std.Io.net;
const mqtt_subprotocol = "mqtt";

fn websocketAcceptOptions(
    allowed_origins: []const []const u8,
) websocket_runtime.AcceptOptions {
    return .{
        .protocols = &.{mqtt_subprotocol},
        .require_subprotocol = true,
        .allowed_origins = allowed_origins,
    };
}

pub const ClientIdentity = vail.tls.client_auth.ClientIdentity;
pub const ClientCertificateVerifier = vail.tls.auth.ClientVerifier;
pub const StapledOcspPolicy = websocket_runtime.StapledOcspPolicy;
pub const HttpProxyOptions = websocket_runtime.HttpProxyOptions;
pub const HttpRedirectPolicy = websocket_runtime.RedirectPolicy;
pub const HttpRedirectProxy = websocket_runtime.RedirectProxy;

pub const HttpRedirectOptions = struct {
    policy: HttpRedirectPolicy = .{},
    proxy: ?HttpRedirectProxy = null,
};

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
        return initValidated(
            allocator,
            try .listen(
                allocator,
                io,
                bind_address,
                websocketLimits(options.limits, options.max_head_bytes),
            ),
            options,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers only when
    /// MQTT listener validation succeeds.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: std.Io.net.Server,
        options: ListenOptions,
    ) runtime.Error!Server {
        try runtime.validateProxyPolicy(options.limits);
        return initValidated(
            allocator,
            .initWithListener(
                allocator,
                io,
                listener,
                websocketLimits(options.limits, options.max_head_bytes),
            ),
            options,
        );
    }

    fn initValidated(
        allocator: std.mem.Allocator,
        websocket_server: websocket_runtime.Server,
        options: ListenOptions,
    ) Server {
        return .{
            .allocator = allocator,
            .websocket_server = websocket_server,
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
        return self.acceptPendingMaybeBefore(options, null);
    }

    pub fn acceptWithDeadline(
        self: *Server,
        options: runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.AcceptedClient {
        var pending = try self.acceptPendingWithDeadline(options, deadline);
        errdefer pending.deinit(self.allocator);
        return pending.finishWithDeadline(options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(
            self.websocket_server.http.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptPendingWithDeadline(
        self: *Server,
        options: runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(
            self.websocket_server.http.io,
            deadline,
        );
        return self.acceptPendingMaybeBefore(options, deadline);
    }

    pub fn acceptPendingWithTimeout(
        self: *Server,
        options: runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptPendingWithDeadline(
            options,
            .fromNow(
                self.websocket_server.http.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn acceptPendingMaybeBefore(
        self: *Server,
        options: runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        const stream = if (deadline) |absolute|
            try accept_deadline.withDeadline(
                &self.websocket_server.http.listener,
                self.websocket_server.http.io,
                absolute,
            )
        else
            try self.websocket_server.http.listener.accept(
                self.websocket_server.http.io,
            );
        return self.acceptStreamPendingMaybeBefore(stream, options, deadline);
    }

    fn acceptStreamPendingMaybeBefore(
        self: *Server,
        stream: net.Stream,
        options: runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.websocket_server.http.io);
        var proxy_metadata = try runtime.readProxyMetadata(
            self.allocator,
            self.websocket_server.http.io,
            stream,
            self.limits,
            deadline,
        );
        errdefer if (proxy_metadata) |*metadata| metadata.deinit();
        const http_connection = try self.websocket_server.http.acceptStream(
            stream,
        );
        stream_owned = false;
        // acceptHttpConnection owns the HTTP connection on every return path.
        const accept_options: websocket_runtime.AcceptOptions = .{
            .protocols = &.{mqtt_subprotocol},
            .require_subprotocol = true,
            .allowed_origins = self.allowed_origins,
        };
        var ws = if (deadline) |absolute|
            try self.websocket_server.acceptHttpConnectionWithDeadline(
                http_connection,
                accept_options,
                absolute,
            )
        else
            try self.websocket_server.acceptHttpConnection(
                http_connection,
                accept_options,
            );
        var ws_owned = true;
        errdefer if (ws_owned) ws.close();

        ws_owned = false;
        var connection = try runtime.Connection.initWebSocket(
            self.allocator,
            ws,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        errdefer connection.close();
        if (proxy_metadata) |metadata| {
            try connection.attachProxyMetadata(metadata);
            proxy_metadata = null;
        }
        return if (deadline) |absolute|
            connection.acceptPendingWithDeadline(options, absolute)
        else
            connection.acceptPending(options);
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

    pub fn serveUntil(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        max_connections: usize,
        accept_options: runtime.AcceptOptions,
        serve_options: runtime.ServeUntilOptions,
    ) anyerror!void {
        return runtime.serveSourceUntil(
            self.pendingSource(),
            self.websocket_server.http.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
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
        return self.acceptPendingMaybeBefore(options, null);
    }

    pub fn acceptWithDeadline(
        self: *UnixServer,
        options: runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.AcceptedClient {
        var pending = try self.acceptPendingWithDeadline(options, deadline);
        errdefer pending.deinit(self.allocator);
        return pending.finishWithDeadline(options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        options: runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(
            self.websocket_server.http.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptPendingWithDeadline(
        self: *UnixServer,
        options: runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(
            self.websocket_server.http.io,
            deadline,
        );
        return self.acceptPendingMaybeBefore(options, deadline);
    }

    pub fn acceptPendingWithTimeout(
        self: *UnixServer,
        options: runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.websocket_server.http.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const ws = try self.websocket_server.acceptWithDeadline(
            websocketAcceptOptions(self.allowed_origins),
            deadline,
        );
        return self.finishPendingWebSocket(ws, options, deadline);
    }

    fn acceptPendingMaybeBefore(
        self: *UnixServer,
        options: runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        const ws = if (deadline) |absolute|
            try self.websocket_server.acceptWithDeadline(
                websocketAcceptOptions(self.allowed_origins),
                absolute,
            )
        else
            try self.websocket_server.accept(.{
                .protocols = &.{mqtt_subprotocol},
                .require_subprotocol = true,
                .allowed_origins = self.allowed_origins,
            });
        return self.finishPendingWebSocket(ws, options, deadline);
    }

    fn finishPendingWebSocket(
        self: *UnixServer,
        ws_value: websocket_runtime.Connection,
        options: runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        var ws = ws_value;
        var ws_owned = true;
        errdefer if (ws_owned) ws.close();
        ws_owned = false;
        var connection = try runtime.Connection.initWebSocket(
            self.allocator,
            ws,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        errdefer connection.close();
        return if (deadline) |absolute|
            connection.acceptPendingWithDeadline(options, absolute)
        else
            connection.acceptPending(options);
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

    pub fn serveUntil(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        max_connections: usize,
        accept_options: runtime.AcceptOptions,
        serve_options: runtime.ServeUntilOptions,
    ) anyerror!void {
        return runtime.serveSourceUntil(
            self.pendingSource(),
            self.websocket_server.http.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
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
        return initValidated(
            allocator,
            try .listen(
                allocator,
                io,
                bind_address,
                websocketTlsOptions(options),
            ),
            options,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers only when
    /// MQTT and TLS listener validation succeeds.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: std.Io.net.Server,
        options: TlsListenOptions,
    ) runtime.Error!TlsServer {
        try runtime.validateProxyPolicy(options.limits);
        return initValidated(
            allocator,
            try .initWithListener(
                allocator,
                io,
                listener,
                websocketTlsOptions(options),
            ),
            options,
        );
    }

    fn websocketTlsOptions(
        options: TlsListenOptions,
    ) websocket_runtime.TlsListenOptions {
        return .{
            .identity = options.identity,
            .identity_provider = options.identity_provider,
            .limits = websocketLimits(
                options.limits,
                options.max_head_bytes,
            ),
            .cipher_suites = options.cipher_suites,
            .tls12_cipher_suites = options.tls12_cipher_suites,
            .protocol_policy = options.protocol_policy,
            .tls13_session_tickets = options.tls13_session_tickets,
            .tls12_session_tickets = options.tls12_session_tickets,
            .max_client_hello_size = options.max_client_hello_size,
            .max_client_handshake_size = options.max_client_handshake_size,
            .tls_handshake_timeout = options.tls_handshake_timeout,
            .client_auth = options.client_auth,
            .alpn_protocols = options.alpn_protocols,
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    fn initValidated(
        allocator: std.mem.Allocator,
        websocket_server: websocket_runtime.TlsServer,
        options: TlsListenOptions,
    ) TlsServer {
        return .{
            .allocator = allocator,
            .websocket_server = websocket_server,
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
        return self.acceptPendingMaybeBefore(options, null);
    }

    pub fn acceptWithDeadline(
        self: *TlsServer,
        options: runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.AcceptedClient {
        var pending = try self.acceptPendingWithDeadline(options, deadline);
        errdefer pending.deinit(self.allocator);
        return pending.finishWithDeadline(options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        options: runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(
            self.websocket_server.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptPendingWithDeadline(
        self: *TlsServer,
        options: runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(
            self.websocket_server.io,
            deadline,
        );
        return self.acceptPendingMaybeBefore(options, deadline);
    }

    pub fn acceptPendingWithTimeout(
        self: *TlsServer,
        options: runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptPendingWithDeadline(
            options,
            .fromNow(
                self.websocket_server.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn acceptPendingMaybeBefore(
        self: *TlsServer,
        options: runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        const stream = if (deadline) |absolute|
            try accept_deadline.withDeadline(
                &self.websocket_server.listener,
                self.websocket_server.io,
                absolute,
            )
        else
            try self.websocket_server.listener.accept(
                self.websocket_server.io,
            );
        return self.acceptStreamPendingMaybeBefore(stream, options, deadline);
    }

    fn acceptStreamPendingMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        options: runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.PendingAcceptedClient {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.websocket_server.io);
        var proxy_metadata = try runtime.readProxyMetadata(
            self.allocator,
            self.websocket_server.io,
            stream,
            self.limits,
            deadline,
        );
        errdefer if (proxy_metadata) |*metadata| metadata.deinit();
        // acceptStream owns the socket on both success and failure.
        stream_owned = false;
        var ws = if (deadline) |absolute|
            try self.websocket_server.acceptStreamWithDeadline(
                stream,
                websocketAcceptOptions(self.allowed_origins),
                absolute,
            )
        else
            try self.websocket_server.acceptStream(
                stream,
                websocketAcceptOptions(self.allowed_origins),
            );
        var ws_owned = true;
        errdefer if (ws_owned) ws.close();

        ws_owned = false;
        var connection = try runtime.Connection.initWebSocket(
            self.allocator,
            ws,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        errdefer connection.close();
        if (proxy_metadata) |metadata| {
            try connection.attachProxyMetadata(metadata);
            proxy_metadata = null;
        }
        return if (deadline) |absolute|
            connection.acceptPendingWithDeadline(options, absolute)
        else
            connection.acceptPending(options);
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

    pub fn serveUntil(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        max_connections: usize,
        accept_options: runtime.AcceptOptions,
        serve_options: runtime.ServeUntilOptions,
    ) anyerror!void {
        return runtime.serveSourceUntil(
            self.pendingSource(),
            self.websocket_server.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

pub const TlsListenOptions = struct {
    identity: @import("vail").tls.auth.ServerIdentity,
    identity_provider: ?@import("../tls/mod.zig").stream.ServerIdentityProvider = null,
    limits: runtime.Limits = .{},
    max_head_bytes: usize = 64 * 1024,
    cipher_suites: []const @import("vail").tls.cipher_suite.Suite =
        &@import("vail").tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const @import("vail").tls.tls12.Suite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    tls13_session_tickets: ?tls_stream.Tls13ServerTicketPolicy = null,
    tls12_session_tickets: ?tls_stream.Tls12ServerTicketPolicy = null,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute TLS handshake receive budget before the HTTP Upgrade budget.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?@import("vail").tls.client_auth.ServerPolicy = null,
    /// Optional TLS ALPN selection before the HTTP/1.1 WebSocket Upgrade.
    alpn_protocols: []const []const u8 = &.{},
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

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectWithConnAckWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithConnAckWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        if (options.client_identity != null) return error.UnsupportedScheme;
        const ws = try websocket_runtime.Client.connectWithDeadline(
            allocator,
            io,
            address,
            websocketConnectOptions(options),
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Resolve a hostname and establish cleartext MQTT-over-WebSocket. The
    /// HTTP Host authority is synthesized by the underlying WebSocket client
    /// when `options.host` is empty, while an explicit override is preserved.
    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectHostWithConnAck(
            allocator,
            io,
            host,
            port,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        if (options.client_identity != null or options.use_vail_tls) {
            return error.UnsupportedScheme;
        }
        const ws = try websocket_runtime.Client.connectHost(
            allocator,
            io,
            host,
            port,
            websocketConnectOptions(options),
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectHostWithConnAckWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithConnAckWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        if (options.client_identity != null or options.use_vail_tls) {
            return error.UnsupportedScheme;
        }
        const ws = try websocket_runtime.Client.connectHostWithDeadline(
            allocator,
            io,
            host,
            port,
            websocketConnectOptions(options),
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Resolve a hostname and establish MQTT-over-WebSocket over TLS. The
    /// hostname supplies both DNS resolution and certificate identity; TLS
    /// credentials and verification remain in `ConnectOptions`.
    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectTlsHostWithConnAck(
            allocator,
            io,
            host,
            port,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectTlsHostWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectTlsHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectTlsHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectTlsHost(
            allocator,
            io,
            host,
            port,
            websocketConnectOptions(options),
            options.tls,
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectTlsHostWithConnAckWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsHostWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectTlsHostWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithConnAckWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            websocketConnectOptions(options),
            options.tls,
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectTlsHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect to a resolved address while keeping an independent hostname
    /// for WSS SNI, certificate verification, and the default HTTP authority.
    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectTlsAddressWithConnAck(
            allocator,
            io,
            address,
            tls_host,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectTlsAddressWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectTlsAddressAttempt(
            allocator,
            io,
            address,
            tls_host,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectTlsAddressAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectTlsAddress(
            allocator,
            io,
            address,
            tls_host,
            websocketConnectOptions(options),
            options.tls,
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectTlsAddressWithConnAckWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsAddressWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectTlsAddressWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithConnAckWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsAddressAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            websocketConnectOptions(options),
            options.tls,
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectTlsAddressAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectUnixWithConnAckWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUnixWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUnixWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUnixAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUnixWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithConnAckWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUnixAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        if (options.client_identity != null or options.use_vail_tls) {
            return error.UnsupportedScheme;
        }
        var ws_options = websocketConnectOptions(options);
        ws_options.tcp_nodelay = false;
        const ws = try websocket_runtime.Client.connectUnixWithDeadline(
            allocator,
            io,
            address,
            ws_options,
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectUnixAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriWithConnAckWithDeadline(
            allocator,
            io,
            uri,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithDeadline(
            allocator,
            io,
            uri,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriAttemptWithDeadline(
            allocator,
            io,
            uri,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithConnAckWithDeadline(
            allocator,
            io,
            uri,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Apply one absolute deadline to DNS/TCP, optional TLS, HTTP Upgrade,
    /// MQTT CONNECT, enhanced authentication, and final CONNACK. Each existing
    /// phase timeout can only shorten that outer budget.
    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectUriTlsWithDeadline(
            allocator,
            io,
            uri,
            websocketConnectOptions(options),
            options.tls,
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectUriAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAttemptWithDeadline(
            allocator,
            io,
            uri,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Follow bounded HTTP Upgrade redirects before sending MQTT CONNECT.
    /// WebSocket redirect security policy controls downgrade, cross-origin
    /// headers/client identity, loops, and optional proxy routing. The TLS
    /// options remain sourced from `ConnectOptions` so callers configure one
    /// WSS trust/identity policy for the complete MQTT connection attempt.
    pub fn connectUriFollowingHttpRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriFollowingHttpRedirectsWithConnAck(
            allocator,
            io,
            uri,
            options,
            redirect_options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriFollowingHttpRedirectsWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriFollowingHttpRedirectsAttempt(
            allocator,
            io,
            uri,
            options,
            redirect_options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriFollowingHttpRedirectsAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        var result = try connectUriFollowingHttpRedirectsDetailedAttempt(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            null,
        );
        return result.takeAttempt();
    }

    pub fn connectUriFollowingHttpRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriFollowingHttpRedirectsWithConnAckWithDeadline(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriFollowingHttpRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingHttpRedirectsWithDeadline(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriFollowingHttpRedirectsWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriFollowingHttpRedirectsAttemptWithDeadline(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriFollowingHttpRedirectsWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingHttpRedirectsWithConnAckWithDeadline(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Apply one absolute deadline across the entire HTTP redirect chain,
    /// final WebSocket Upgrade, MQTT CONNECT, enhanced authentication, and
    /// CONNACK. No redirect or partial protocol progress renews the budget.
    pub fn connectUriFollowingHttpRedirectsAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        var result = try connectUriFollowingHttpRedirectsDetailedAttempt(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return result.takeAttempt();
    }

    pub fn connectUriFollowingHttpRedirectsAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
        redirect_options: HttpRedirectOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingHttpRedirectsAttemptWithDeadline(
            allocator,
            io,
            uri,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Establish MQTT over WS/WSS through a cleartext HTTP CONNECT proxy.
    /// Proxy headers are confined to CONNECT; `ConnectOptions.extra_headers`
    /// remain on the end-to-end WebSocket Upgrade. The MQTT subprotocol and
    /// CONNECT/CONNACK exchange then use that accepted tunnel.
    pub fn connectUriViaProxy(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriViaProxyWithConnAck(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriViaProxyWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriViaProxyAttempt(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriViaProxyAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectUriViaProxy(
            allocator,
            io,
            proxy_uri,
            uri,
            websocketConnectOptions(options),
            proxy_options,
            options.tls,
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectUriViaProxyWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriViaProxyWithConnAckWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriViaProxyWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaProxyWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriViaProxyWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriViaProxyAttemptWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriViaProxyWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaProxyWithConnAckWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Apply one absolute deadline across proxy DNS/TCP, CONNECT, optional
    /// origin TLS, WebSocket Upgrade, MQTT CONNECT, enhanced authentication,
    /// and final CONNACK. Per-phase limits can only shorten this budget.
    pub fn connectUriViaProxyAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectUriViaProxyWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri,
            websocketConnectOptions(options),
            proxy_options,
            options.tls,
            deadline,
        );
        return connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            deadline,
        );
    }

    pub fn connectUriViaProxyAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaProxyAttemptWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri,
            options,
            proxy_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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
        return connectUriFollowingRedirectsMaybeProxy(
            allocator,
            io,
            uri_text,
            options,
            policy,
            null,
            null,
            null,
        );
    }

    /// Follow the complete redirect chain under one caller-owned deadline.
    /// A successful or refused hop cannot renew the remaining budget.
    pub fn connectUriFollowingRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        policy: redirect.Policy,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        return connectUriFollowingRedirectsMaybeProxy(
            allocator,
            io,
            uri_text,
            options,
            policy,
            null,
            null,
            deadline,
        );
    }

    pub fn connectUriFollowingRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        policy: redirect.Policy,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingRedirectsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            policy,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Follow MQTT 5 WS/WSS redirects while opening every authority through
    /// the same cleartext HTTP proxy. Each redirect receives a fresh CONNECT;
    /// proxy-only headers remain outside every origin Upgrade request.
    pub fn connectUriViaProxyFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        policy: redirect.Policy,
    ) runtime.Error!runtime.ConnectResult {
        return connectUriFollowingRedirectsMaybeProxy(
            allocator,
            io,
            uri_text,
            options,
            policy,
            null,
            .{ .uri = proxy_uri, .options = proxy_options },
            null,
        );
    }

    /// Preserve one absolute deadline across every proxy CONNECT and
    /// redirected origin handshake in the chain.
    pub fn connectUriViaProxyFollowingRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        policy: redirect.Policy,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        return connectUriFollowingRedirectsMaybeProxy(
            allocator,
            io,
            uri_text,
            options,
            policy,
            null,
            .{ .uri = proxy_uri, .options = proxy_options },
            deadline,
        );
    }

    pub fn connectUriViaProxyFollowingRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        policy: redirect.Policy,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaProxyFollowingRedirectsWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            policy,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Follow both HTTP Upgrade redirects and MQTT 5 Server Reference
    /// redirects. Every MQTT authority receives its own bounded HTTP redirect
    /// chain, while loop/authorization policy remains independent at each
    /// protocol layer.
    pub fn connectUriFollowingAllRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        http_redirect_options: HttpRedirectOptions,
        mqtt_policy: redirect.Policy,
    ) runtime.Error!runtime.ConnectResult {
        return connectUriFollowingRedirectsMaybeProxy(
            allocator,
            io,
            uri_text,
            options,
            mqtt_policy,
            http_redirect_options,
            null,
            null,
        );
    }

    /// Preserve one absolute caller budget across both nested redirect layers,
    /// every network/TLS/Upgrade attempt, MQTT enhanced authentication, and the
    /// final CONNACK.
    pub fn connectUriFollowingAllRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        http_redirect_options: HttpRedirectOptions,
        mqtt_policy: redirect.Policy,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectResult {
        return connectUriFollowingRedirectsMaybeProxy(
            allocator,
            io,
            uri_text,
            options,
            mqtt_policy,
            http_redirect_options,
            null,
            deadline,
        );
    }

    pub fn connectUriFollowingAllRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        http_redirect_options: HttpRedirectOptions,
        mqtt_policy: redirect.Policy,
        timeout: std.Io.Duration,
    ) runtime.Error!runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingAllRedirectsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            http_redirect_options,
            mqtt_policy,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }
};

pub const ConnectOptions = struct {
    mqtt: runtime.ConnectOptions,
    host: []const u8 = "",
    target: []const u8 = "/mqtt",
    /// Optional browser Origin header.
    origin: ?[]const u8 = null,
    /// Additional end-to-end WebSocket Upgrade fields such as Authorization
    /// or Cookie. Proxy credentials belong in `HttpProxyOptions` instead.
    extra_headers: []const http1.Header = &.{},
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
    /// Stapled OCSP verification for vail-backed WSS connections.
    stapled_ocsp: StapledOcspPolicy = .ignore,
    /// Emit status_request on vail-backed WSS. Must remain enabled for
    /// `.require` and defaults on for RFC 7633 Must-Staple compatibility.
    request_ocsp: bool = true,
    /// Ordered TLS ALPN offers for WSS, typically `http/1.1`.
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const vail.tls.tls12.Suite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls13_only,
    request_tls12_session_ticket: bool = true,
    tls12_ticket_resumption: ?*const tls_stream.Tls12SessionTicket = null,
    request_tls13_session_ticket: bool = true,
    tls13_ticket_resumption: ?*const tls_stream.Tls13SessionTicket = null,
    max_server_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget for the vail WSS client handshake.
    tls_handshake_timeout: ?std.Io.Duration = null,
};

const ProxyTarget = struct {
    uri: []const u8,
    options: HttpProxyOptions,
};

const HttpRedirectAttempt = struct {
    allocator: std.mem.Allocator,
    attempt: runtime.ConnectAttempt,
    final_uri: []u8,

    fn deinit(self: *HttpRedirectAttempt) void {
        const allocator = self.allocator;
        self.attempt.deinit(allocator);
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    fn takeAttempt(self: *HttpRedirectAttempt) runtime.ConnectAttempt {
        const attempt = self.attempt;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return attempt;
    }
};

fn connectUriFollowingHttpRedirectsDetailedAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    options: ConnectOptions,
    redirect_options: HttpRedirectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) runtime.Error!HttpRedirectAttempt {
    var ws_result = if (deadline) |absolute|
        try websocket_runtime.Client
            .connectUriFollowingRedirectsDetailedAttemptWithDeadline(
            allocator,
            io,
            uri,
            websocketConnectOptions(options),
            websocketRedirectOptions(options, redirect_options),
            absolute,
        )
    else
        try websocket_runtime.Client.connectUriFollowingRedirectsDetailedAttempt(
            allocator,
            io,
            uri,
            websocketConnectOptions(options),
            websocketRedirectOptions(options, redirect_options),
        );
    var ws_result_owned = true;
    errdefer if (ws_result_owned) ws_result.deinit();
    const final_uri = ws_result.final_uri;
    const ws = try ws_result.attempt.requireAccepted();
    ws_result_owned = false;
    ws_result = undefined;
    errdefer allocator.free(final_uri);
    const attempt = if (deadline) |absolute|
        try connectWebSocketAttemptBefore(
            allocator,
            ws,
            options.mqtt,
            absolute,
        )
    else
        try connectWebSocketAttempt(allocator, ws, options.mqtt);
    return .{
        .allocator = allocator,
        .attempt = attempt,
        .final_uri = final_uri,
    };
}

fn connectUriFollowingRedirectsMaybeProxy(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri_text: []const u8,
    options: ConnectOptions,
    policy: redirect.Policy,
    http_redirect_options: ?HttpRedirectOptions,
    proxy: ?ProxyTarget,
    deadline: ?std.Io.Clock.Timestamp,
) runtime.Error!runtime.ConnectResult {
    const usable_deadline = if (deadline) |absolute|
        try deadline_policy.usableAwake(io, absolute)
    else
        null;
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
        var actual_http_uri: ?[]u8 = null;
        defer if (actual_http_uri) |owned| allocator.free(owned);
        var attempt = if (http_redirect_options) |http_redirect| blk: {
            var result = if (usable_deadline) |absolute|
                try connectUriFollowingHttpRedirectsDetailedAttempt(
                    allocator,
                    io,
                    target.uri,
                    options,
                    http_redirect,
                    absolute,
                )
            else
                try connectUriFollowingHttpRedirectsDetailedAttempt(
                    allocator,
                    io,
                    target.uri,
                    options,
                    http_redirect,
                    null,
                );
            actual_http_uri = result.final_uri;
            const inner = result.attempt;
            result = undefined;
            break :blk inner;
        } else if (proxy) |route|
            if (usable_deadline) |absolute|
                try Client.connectUriViaProxyAttemptWithDeadline(
                    allocator,
                    io,
                    route.uri,
                    target.uri,
                    options,
                    route.options,
                    absolute,
                )
            else
                try Client.connectUriViaProxyAttempt(
                    allocator,
                    io,
                    route.uri,
                    target.uri,
                    options,
                    route.options,
                )
        else if (usable_deadline) |absolute|
            try Client.connectUriAttemptWithDeadline(
                allocator,
                io,
                target.uri,
                options,
                absolute,
            )
        else
            try Client.connectUriAttempt(
                allocator,
                io,
                target.uri,
                options,
            );
        errdefer attempt.deinit(allocator);
        if (attempt.accepted()) return attempt.requireAccepted();
        const redirect_from_uri = actual_http_uri orelse current_uri;
        if (actual_http_uri != null) {
            try chain.recordInitial(
                redirect_from_uri,
                try websocketRedirectTransport(redirect_from_uri),
            );
        }
        const reference = (try redirect.referenceForConnAck(
            attempt.connack.connack,
        )) orelse return error.ConnectRefused;
        var next = try chain.follow(
            redirect_from_uri,
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

fn websocketRedirectTransport(
    uri_text: []const u8,
) runtime.Error!redirect.Transport {
    const uri = std.Uri.parse(uri_text) catch
        return error.InvalidServerReference;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "ws")) return .websocket;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "wss")) return .websocket_tls;
    return error.UnsupportedRedirectScheme;
}

/// Borrowed WS/WSS target for `mqtt.reconnect.Client`. URI/TLS/WebSocket
/// configuration must remain valid for the reconnect client lifetime.
pub const ReconnectConnector = struct {
    uri: []const u8,
    options: ConnectOptions,

    pub fn connector(self: *ReconnectConnector) runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
            .connect_attempt_with_tls_tickets = connectAttemptWithTlsTickets,
            .connect_attempt_with_tls_tickets_deadline = connectAttemptWithTlsTicketsAndDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriAttempt(
            allocator,
            io,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriAttemptWithDeadline(
            allocator,
            io,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriAttempt(
            allocator,
            io,
            self.uri,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriAttemptWithDeadline(
            allocator,
            io,
            self.uri,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            deadline,
        );
    }
};

/// Borrowed WS/WSS target and cleartext HTTP proxy for
/// `mqtt.reconnect.Client`. URI, TLS, WebSocket, proxy-header, and certificate
/// storage must remain valid for the reconnect client lifetime. Every attempt
/// creates a new CONNECT tunnel; WSS ticket resumption is forwarded unchanged.
pub const ProxyReconnectConnector = struct {
    proxy_uri: []const u8,
    uri: []const u8,
    options: ConnectOptions,
    proxy_options: HttpProxyOptions = .{},

    pub fn connector(self: *ProxyReconnectConnector) runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
            .connect_attempt_with_tls_tickets = connectAttemptWithTlsTickets,
            .connect_attempt_with_tls_tickets_deadline = connectAttemptWithTlsTicketsAndDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ProxyReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriViaProxyAttempt(
            allocator,
            io,
            self.proxy_uri,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
            self.proxy_options,
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ProxyReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriViaProxyAttemptWithDeadline(
            allocator,
            io,
            self.proxy_uri,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
            self.proxy_options,
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ProxyReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriViaProxyAttempt(
            allocator,
            io,
            self.proxy_uri,
            self.uri,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            self.proxy_options,
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *ProxyReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriViaProxyAttemptWithDeadline(
            allocator,
            io,
            self.proxy_uri,
            self.uri,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            self.proxy_options,
            deadline,
        );
    }
};

/// Borrowed WS/WSS URI plus bounded HTTP redirect policy for
/// `mqtt.reconnect.Client`. Each reconnect attempt starts a fresh redirect
/// chain. TLS tickets are applied to the initial same-origin attempt; the
/// WebSocket redirect policy clears them before any cross-origin hop.
pub const HttpRedirectReconnectConnector = struct {
    uri: []const u8,
    options: ConnectOptions,
    redirect_options: HttpRedirectOptions = .{},

    pub fn connector(
        self: *HttpRedirectReconnectConnector,
    ) runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
            .connect_attempt_with_tls_tickets = connectAttemptWithTlsTickets,
            .connect_attempt_with_tls_tickets_deadline = connectAttemptWithTlsTicketsAndDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *HttpRedirectReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectUriFollowingHttpRedirectsAttempt(
            allocator,
            io,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
            self.redirect_options,
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *HttpRedirectReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectUriFollowingHttpRedirectsAttemptWithDeadline(
            allocator,
            io,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
            self.redirect_options,
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *HttpRedirectReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectUriFollowingHttpRedirectsAttempt(
            allocator,
            io,
            self.uri,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            self.redirect_options,
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *HttpRedirectReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectUriFollowingHttpRedirectsAttemptWithDeadline(
            allocator,
            io,
            self.uri,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            self.redirect_options,
            deadline,
        );
    }
};

/// Borrowed cleartext WebSocket hostname target for the reconnect client. Each
/// attempt re-runs DNS under the connector-owned network timeout. TLS client
/// configuration is rejected by the same public hostname path rather than
/// silently ignored.
pub const HostReconnectConnector = struct {
    host: []const u8,
    port: u16,
    options: ConnectOptions,

    pub fn connector(self: *HostReconnectConnector) runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *HostReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectHostAttempt(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptions(self.options, mqtt_options),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *HostReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectHostAttemptWithDeadline(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptions(self.options, mqtt_options),
            deadline,
        );
    }
};

/// Borrowed WSS hostname target for the reconnect client. The hostname is
/// resolved again and used as TLS SNI/certificate identity on every attempt.
pub const TlsHostReconnectConnector = struct {
    host: []const u8,
    port: u16,
    options: ConnectOptions,

    pub fn connector(
        self: *TlsHostReconnectConnector,
    ) runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
            .connect_attempt_with_tls_tickets = connectAttemptWithTlsTickets,
            .connect_attempt_with_tls_tickets_deadline = connectAttemptWithTlsTicketsAndDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsHostReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectTlsHostAttempt(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptions(self.options, mqtt_options),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsHostReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptions(self.options, mqtt_options),
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsHostReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectTlsHostAttempt(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsHostReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            deadline,
        );
    }
};

/// Borrowed fixed-address WSS target with independent certificate identity.
/// This avoids DNS when an application already owns endpoint discovery while
/// preserving SNI and hostname verification on every reconnect attempt.
pub const TlsAddressReconnectConnector = struct {
    address: net.IpAddress,
    tls_host: []const u8,
    options: ConnectOptions,

    pub fn connector(
        self: *TlsAddressReconnectConnector,
    ) runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
            .connect_attempt_with_tls_tickets = connectAttemptWithTlsTickets,
            .connect_attempt_with_tls_tickets_deadline = connectAttemptWithTlsTicketsAndDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsAddressReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectTlsAddressAttempt(
            allocator,
            io,
            self.address,
            self.tls_host,
            reconnectOptions(self.options, mqtt_options),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsAddressReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            self.address,
            self.tls_host,
            reconnectOptions(self.options, mqtt_options),
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsAddressReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectTlsAddressAttempt(
            allocator,
            io,
            self.address,
            self.tls_host,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: runtime.ConnectOptions,
        tickets: runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        const self: *TlsAddressReconnectConnector =
            @ptrCast(@alignCast(context));
        return Client.connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            self.address,
            self.tls_host,
            reconnectOptionsWithTlsTickets(
                self.options,
                mqtt_options,
                tickets,
            ),
            deadline,
        );
    }
};

fn reconnectOptions(
    configured: ConnectOptions,
    mqtt_options: runtime.ConnectOptions,
) ConnectOptions {
    var options = configured;
    const network_connect_timeout = options.mqtt.network_connect_timeout;
    const address_resolver = options.mqtt.address_resolver orelse
        mqtt_options.address_resolver;
    options.mqtt = mqtt_options;
    options.mqtt.network_connect_timeout = network_connect_timeout;
    options.mqtt.address_resolver = address_resolver;
    return options;
}

test "MQTT WebSocket reconnect resolver inherits with connector override" {
    const Resolver = struct {
        fn resolve(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            return error.UnknownHostName;
        }
    };
    var inherited_context: u8 = 0;
    var override_context: u8 = 0;
    const inherited: runtime.AddressResolver = .{
        .context = &inherited_context,
        .resolve = Resolver.resolve,
    };
    const override: runtime.AddressResolver = .{
        .context = &override_context,
        .resolve = Resolver.resolve,
    };
    const from_client = reconnectOptions(
        .{ .mqtt = .{ .client_id = "configured" } },
        .{ .client_id = "owned", .address_resolver = inherited },
    );
    try std.testing.expectEqual(
        @intFromPtr(inherited.context),
        @intFromPtr(from_client.mqtt.address_resolver.?.context),
    );
    const from_connector = reconnectOptions(
        .{ .mqtt = .{
            .client_id = "configured",
            .address_resolver = override,
        } },
        .{ .client_id = "owned", .address_resolver = inherited },
    );
    try std.testing.expectEqual(
        @intFromPtr(override.context),
        @intFromPtr(from_connector.mqtt.address_resolver.?.context),
    );
}

fn reconnectOptionsWithTlsTickets(
    configured: ConnectOptions,
    mqtt_options: runtime.ConnectOptions,
    tickets: runtime.ClientTlsSessionTickets,
) ConnectOptions {
    var options = reconnectOptions(configured, mqtt_options);
    if (tickets.tls12) |ticket| options.tls12_ticket_resumption = ticket;
    if (tickets.tls13) |ticket| options.tls13_ticket_resumption = ticket;
    return options;
}

fn websocketLimits(
    limits: runtime.Limits,
    max_head_bytes: usize,
) websocket_runtime.Limits {
    return .{
        .max_head_bytes = max_head_bytes,
        .max_frame_bytes = limits.max_packet_size,
        .max_message_bytes = limits.max_packet_size,
        .tcp_nodelay = limits.tcp_nodelay,
        .tcp_keepalive = limits.tcp_keepalive,
        .tcp_user_timeout_ms = limits.tcp_user_timeout_ms,
    };
}

test "MQTT WebSocket limits preserve TCP socket policy" {
    const enabled = websocketLimits(.{
        .tcp_nodelay = true,
        .tcp_keepalive = .{
            .idle_seconds = 31,
            .interval_seconds = 11,
            .probe_count = 7,
        },
        .tcp_user_timeout_ms = 12_345,
    }, 1234);
    try std.testing.expect(enabled.tcp_nodelay);
    try std.testing.expectEqual(
        runtime.TcpKeepAlive{
            .idle_seconds = 31,
            .interval_seconds = 11,
            .probe_count = 7,
        },
        enabled.tcp_keepalive.?,
    );
    try std.testing.expectEqual(@as(?u32, 12_345), enabled.tcp_user_timeout_ms);

    const defaults = websocketLimits(.{ .tcp_nodelay = false }, 1234);
    try std.testing.expect(!defaults.tcp_nodelay);
    try std.testing.expectEqual(
        @as(?runtime.TcpKeepAlive, null),
        defaults.tcp_keepalive,
    );
    try std.testing.expectEqual(@as(?u32, null), defaults.tcp_user_timeout_ms);

    const Resolver = struct {
        fn resolve(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            return error.UnknownHostName;
        }
    };
    var resolver_context: u8 = 0;
    const client = websocketConnectOptions(.{
        .mqtt = .{
            .client_id = "socket-policy",
            .limits = .{ .tcp_user_timeout_ms = 54_321 },
            .address_resolver = .{
                .context = &resolver_context,
                .resolve = Resolver.resolve,
            },
        },
    });
    try std.testing.expectEqual(
        @as(?u32, 54_321),
        client.tcp_user_timeout_ms,
    );
    try std.testing.expectEqual(
        @intFromPtr(&resolver_context),
        @intFromPtr(client.address_resolver.?.context),
    );

    const ocsp = websocketConnectOptions(.{
        .mqtt = .{ .client_id = "ocsp-policy" },
        .stapled_ocsp = .require,
        .request_ocsp = true,
    });
    try std.testing.expect(ocsp.vail_tls != null);
    try std.testing.expectEqual(
        StapledOcspPolicy.require,
        ocsp.vail_tls.?.stapled_ocsp,
    );
    try std.testing.expect(ocsp.vail_tls.?.request_ocsp);

    const redirected = websocketRedirectOptions(
        .{
            .mqtt = .{ .client_id = "redirect-policy" },
            .tls = .{ .verify_host = false },
        },
        .{
            .policy = .{ .max_redirects = 7 },
            .proxy = .{ .uri = "http://proxy.example:8080" },
        },
    );
    try std.testing.expectEqual(@as(usize, 7), redirected.policy.max_redirects);
    try std.testing.expect(!redirected.tls.verify_host);
    try std.testing.expectEqualStrings(
        "http://proxy.example:8080",
        redirected.proxy.?.uri,
    );
}

fn websocketConnectOptions(
    options: ConnectOptions,
) websocket_runtime.ConnectOptions {
    return .{
        .host = options.host,
        .target = options.target,
        .origin = options.origin,
        .extra_headers = options.extra_headers,
        .protocols = &.{mqtt_subprotocol},
        .tcp_nodelay = options.tcp_nodelay,
        .tcp_keepalive = options.mqtt.limits.tcp_keepalive,
        .tcp_user_timeout_ms = options.mqtt.limits.tcp_user_timeout_ms,
        .connect_timeout = options.mqtt.network_connect_timeout,
        .address_resolver = options.mqtt.address_resolver,
        .tls_handshake_timeout = options.tls_handshake_timeout,
        .limits = websocketLimits(
            options.mqtt.limits,
            options.max_head_bytes,
        ),
        .vail_tls = if (options.use_vail_tls or
            options.protocol_policy != .tls13_only or
            options.client_identity != null or
            options.server_verifier != null or
            options.stapled_ocsp != .ignore)
            .{
                .identity = options.client_identity,
                .server_verifier = options.server_verifier,
                .stapled_ocsp = options.stapled_ocsp,
                .request_ocsp = options.request_ocsp,
                .alpn_protocols = options.alpn_protocols,
                .cipher_suites = options.cipher_suites,
                .tls12_cipher_suites = options.tls12_cipher_suites,
                .protocol_policy = options.protocol_policy,
                .request_tls12_session_ticket = options.request_tls12_session_ticket,
                .tls12_ticket_resumption = options.tls12_ticket_resumption,
                .request_tls13_session_ticket = options.request_tls13_session_ticket,
                .tls13_ticket_resumption = options.tls13_ticket_resumption,
                .max_server_handshake_size = options.max_server_handshake_size,
                .handshake_timeout = options.tls_handshake_timeout,
            }
        else
            null,
    };
}

fn websocketRedirectOptions(
    options: ConnectOptions,
    redirect_options: HttpRedirectOptions,
) websocket_runtime.RedirectOptions {
    return .{
        .policy = redirect_options.policy,
        .tls = options.tls,
        .proxy = redirect_options.proxy,
    };
}

fn connectWebSocketAttempt(
    allocator: std.mem.Allocator,
    ws: websocket_runtime.Connection,
    options: runtime.ConnectOptions,
) runtime.Error!runtime.ConnectAttempt {
    return connectWebSocketAttemptMaybeBefore(
        allocator,
        ws,
        options,
        null,
    );
}

fn connectWebSocketAttemptBefore(
    allocator: std.mem.Allocator,
    ws: websocket_runtime.Connection,
    options: runtime.ConnectOptions,
    deadline: std.Io.Clock.Timestamp,
) runtime.Error!runtime.ConnectAttempt {
    return connectWebSocketAttemptMaybeBefore(
        allocator,
        ws,
        options,
        deadline,
    );
}

fn connectWebSocketAttemptMaybeBefore(
    allocator: std.mem.Allocator,
    ws: websocket_runtime.Connection,
    options: runtime.ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) runtime.Error!runtime.ConnectAttempt {
    if (ws.selected_protocol == null or
        !std.mem.eql(u8, ws.selected_protocol.?, mqtt_subprotocol))
    {
        var invalid_ws = ws;
        invalid_ws.close();
        return error.InvalidSubprotocol;
    }

    var connection = try runtime.Connection.initWebSocket(
        allocator,
        ws,
        options.protocol,
        options.limits,
        options.max_outgoing_inflight,
        options.topic_alias_maximum,
    );
    connection.max_incoming_inflight = options.effectiveReceiveMaximum();
    connection.setPeerPublishCapabilities(
        options.peer_maximum_qos,
        options.peer_retain_available,
    );
    errdefer connection.close();
    return if (deadline) |absolute|
        connection.establishClientWithDeadline(options, absolute)
    else
        connection.establishClient(options);
}

const std = @import("std");
const net = std.Io.net;
const accept_deadline = @import("../../internal/accept.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const socket_options = @import("../../internal/socket_options.zig");

const runtime = @import("../runtime.zig");
const AcceptOptions = runtime.AcceptOptions;
const AsyncServeError = runtime.AsyncServeError;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const Error = runtime.Error;
const Limits = runtime.Limits;
const PendingUpgrade = runtime.PendingUpgrade;
const ServeUntilOptions = runtime.ServeUntilOptions;
const TlsListenOptions = runtime.TlsListenOptions;
const http1_runtime = runtime.http1_runtime;
const receiveUpgradeRequestFromTransport = runtime.receiveUpgradeRequestFromTransport;
const serveAcceptedConcurrent = runtime.serveAcceptedConcurrent;
const serveAcceptedUntil = runtime.serveAcceptedUntil;
const tls_stream = runtime.tls_stream;

pub const Server = struct {
    http: http1_runtime.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return initWithListener(
            allocator,
            io,
            try bind_address.listen(io, .{ .reuse_address = true }),
            limits,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers to the
    /// returned server, which closes it from `deinit`.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        limits: Limits,
    ) Server {
        return .{
            .http = .initWithListener(allocator, io, listener, .{
                .max_head_bytes = limits.max_head_bytes,
                .max_body_bytes = 0,
            }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.http.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.http.address();
    }

    pub fn accept(self: *Server, options: AcceptOptions) Error!Connection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Apply one caller-owned awake-clock deadline to TCP accept and the
    /// complete HTTP Upgrade.
    pub fn acceptWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithTimeout(
            options,
            timeout,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Upgrade an already accepted HTTP/1 connection. This lets protocol
    /// adapters consume a trusted preface without duplicating WebSocket
    /// handshake validation.
    pub fn acceptHttpConnection(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            null,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Upgrade an accepted HTTP/1 connection before an absolute deadline. The
    /// connection transfers at entry and is closed on every failure path.
    pub fn acceptHttpConnectionWithDeadline(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveHttpUpgradeRequestWithDeadline(
            http_connection,
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptHttpConnectionWithTimeout(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        // The caller retains the HTTP connection if validation fails before
        // the deadline form receives ownership.
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptHttpConnectionWithDeadline(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Receive and validate a WebSocket Upgrade request without sending 101.
    /// The returned value owns the accepted transport until the application
    /// accepts, rejects, or deinitializes it.
    pub fn receiveUpgradeRequest(
        self: *Server,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        const http_connection = try self.http.accept();
        return self.receiveHttpUpgradeRequest(http_connection, options);
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        const http_connection = try self.http.acceptWithDeadline(deadline);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Adopt a caller-accepted TCP stream and stop before the 101 decision.
    pub fn receiveStreamUpgradeRequest(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        const http_connection = try self.http.acceptStream(stream);
        return self.receiveHttpUpgradeRequest(http_connection, options);
    }

    pub fn receiveStreamUpgradeRequestWithDeadline(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        const http_connection = try self.http.acceptStream(stream);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveStreamUpgradeRequestWithTimeout(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamUpgradeRequestWithDeadline(
            stream,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveHttpUpgradeRequest(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            null,
        );
    }

    pub fn receiveHttpUpgradeRequestWithDeadline(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveHttpUpgradeRequestWithTimeout(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveHttpUpgradeRequestWithDeadline(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveHttpUpgradeRequestMaybeBefore(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        var http_conn = http_connection;
        errdefer http_conn.close();
        try socket_options.applyTcp(http_conn.stream, .{
            .no_delay = self.limits.tcp_nodelay,
            .keep_alive = self.limits.tcp_keepalive,
            .user_timeout_ms = self.limits.tcp_user_timeout_ms,
        });

        return receiveUpgradeRequestFromTransport(
            self.http.allocator,
            http_conn.io,
            .{ .tcp = .{
                .io = http_conn.io,
                .stream = http_conn.stream,
            } },
            self.limits,
            options,
            deadline,
        );
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            Server,
            self,
            self.http.io,
            self.http.allocator,
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
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            Server,
            self,
            self.http.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

/// Cleartext WebSocket listener over a Unix-domain stream socket.
///
/// This has the same opening-handshake and frame semantics as `Server`; only
/// socket creation differs. The path remains caller-owned and is not removed
/// automatically on shutdown.
pub const UnixServer = struct {
    http: http1_runtime.UnixServer,
    limits: Limits = .{},

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        limits: Limits,
    ) Error!UnixServer {
        if (limits.tcp_keepalive != null or
            limits.tcp_user_timeout_ms != null)
        {
            return error.SocketOptionUnsupported;
        }
        return .{
            .http = try .listen(allocator, io, address, .{
                .max_head_bytes = limits.max_head_bytes,
                .max_body_bytes = 0,
                // Unix sockets do not implement TCP_NODELAY.
                .tcp_nodelay = false,
            }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *UnixServer) void {
        self.http.deinit();
        self.* = undefined;
    }

    pub fn accept(
        self: *UnixServer,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Apply one caller-owned awake-clock deadline to Unix accept and the
    /// complete HTTP Upgrade.
    pub fn acceptWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithTimeout(
            options,
            timeout,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Receive and validate a Unix-socket Upgrade request without sending 101.
    pub fn receiveUpgradeRequest(
        self: *UnixServer,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveUpgradeRequestMaybeBefore(options, null);
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.receiveUpgradeRequestMaybeBefore(options, deadline);
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveHttpUpgradeRequest(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            null,
        );
    }

    pub fn receiveHttpUpgradeRequestWithDeadline(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveHttpUpgradeRequestWithTimeout(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveHttpUpgradeRequestWithDeadline(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveUpgradeRequestMaybeBefore(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        const http_connection = if (deadline) |absolute|
            try self.http.acceptWithDeadline(absolute)
        else
            try self.http.accept();
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    fn receiveHttpUpgradeRequestMaybeBefore(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        var http_connection_owned = http_connection;
        var http_owned = true;
        errdefer if (http_owned) http_connection_owned.close();
        var limits = self.limits;
        limits.tcp_nodelay = false;
        limits.tcp_keepalive = null;
        limits.tcp_user_timeout_ms = null;
        const pending = try receiveUpgradeRequestFromTransport(
            self.http.allocator,
            self.http.io,
            .{ .tcp = .{
                .io = self.http.io,
                .stream = http_connection_owned.stream,
            } },
            limits,
            options,
            deadline,
        );
        http_owned = false;
        return pending;
    }

    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *Connection,
        ) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            UnixServer,
            self,
            self.http.io,
            self.http.allocator,
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
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            UnixServer,
            self,
            self.http.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

/// TLS 1.3 WebSocket listener.
///
/// TLS termination is performed before the same strict HTTP/1 Upgrade parser
/// used by `Server`, so WSS inherits subprotocol, extension, smuggling and
/// frame-validation behavior rather than maintaining a second handshake path.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,
    limits: Limits,
    tls: tls_stream.ServerOptions,
    tcp_nodelay: bool,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) Error!TlsServer {
        const tls_options = try validatedTlsOptions(options);
        return initValidated(
            allocator,
            io,
            try bind_address.listen(io, .{ .reuse_address = true }),
            options,
            tls_options,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers only when
    /// TLS validation succeeds; the returned server closes it from `deinit`.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        options: TlsListenOptions,
    ) Error!TlsServer {
        return initValidated(
            allocator,
            io,
            listener,
            options,
            try validatedTlsOptions(options),
        );
    }

    fn validatedTlsOptions(
        options: TlsListenOptions,
    ) Error!tls_stream.ServerOptions {
        const tls_options = tls_stream.ServerOptions{
            .identity = options.identity,
            .identity_provider = options.identity_provider,
            .cipher_suites = options.cipher_suites,
            .tls12_cipher_suites = options.tls12_cipher_suites,
            .protocol_policy = options.protocol_policy,
            .tls13_session_tickets = options.tls13_session_tickets,
            .tls12_session_tickets = options.tls12_session_tickets,
            .max_client_hello_size = options.max_client_hello_size,
            .max_client_handshake_size = options.max_client_handshake_size,
            .handshake_timeout = options.tls_handshake_timeout,
            .client_auth = options.client_auth,
            .alpn_protocols = options.alpn_protocols,
        };
        try tls_options.validateIdentity();
        return tls_options;
    }

    fn initValidated(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        options: TlsListenOptions,
        tls_options: tls_stream.ServerOptions,
    ) TlsServer {
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .limits = options.limits,
            .tls = tls_options,
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: TlsServer) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(
        self: *TlsServer,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Carry one caller-owned deadline through TCP accept, TLS, and the HTTP
    /// Upgrade.
    pub fn acceptWithDeadline(
        self: *TlsServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithTimeout(
            options,
            timeout,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Perform TLS and WebSocket handshakes on an already accepted stream.
    pub fn acceptStream(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            null,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptStreamWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveStreamUpgradeRequestWithDeadline(
            stream,
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptStreamWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Complete TLS and validate the HTTP Upgrade without sending 101.
    pub fn receiveUpgradeRequest(
        self: *TlsServer,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        const stream = try self.listener.accept(self.io);
        return self.receiveStreamUpgradeRequest(stream, options);
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *TlsServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            deadline,
        );
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *TlsServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveStreamUpgradeRequest(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            null,
        );
    }

    pub fn receiveStreamUpgradeRequestWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            deadline,
        );
    }

    pub fn receiveStreamUpgradeRequestWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamUpgradeRequestWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveStreamUpgradeRequestMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        try socket_options.applyTcp(stream, .{
            .no_delay = self.tcp_nodelay,
            .keep_alive = self.limits.tcp_keepalive,
            .user_timeout_ms = self.limits.tcp_user_timeout_ms,
        });
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ServerConnection.initWithDeadline(
                self.allocator,
                self.io,
                stream,
                self.tls,
                absolute,
            )
        else
            try tls_stream.ServerConnection.init(
                self.allocator,
                self.io,
                stream,
                self.tls,
            );
        stream_owned = false;
        errdefer tls_connection.deinit();
        return receiveUpgradeRequestFromTransport(
            self.allocator,
            self.io,
            .{ .tls_server = tls_connection },
            self.limits,
            options,
            deadline,
        );
    }

    pub fn serveConcurrent(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *Connection,
        ) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            TlsServer,
            self,
            self.io,
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
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            TlsServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

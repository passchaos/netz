//! HTTP/2 server listeners, TLS adoption, and serve loops.

const std = @import("std");
const http2 = @import("../mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const accept_deadline = @import("../../internal/accept.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const socket_options = @import("../../internal/socket_options.zig");
const vail = @import("vail");

const Error = runtime.Error;
const Limits = runtime.Limits;
const Connection = runtime.Connection;
const OwnedRequest = runtime.OwnedRequest;
const H2cUpgradeRequest = runtime.H2cUpgradeRequest;
const RuntimeTransport = runtime.RuntimeTransport;
const validateLocalLimits = runtime.validateLocalLimits;
const limitsToHttp1 = runtime.limitsToHttp1;
const ResponseOptions = runtime.ResponseOptions;
const terminal_tls_output = @import("control/tls_close.zig");
const validateH2cUpgradeRequest = runtime.validateH2cUpgradeRequest;
const readExactTransportWithDeadline = runtime.readExactTransportWithDeadline;
const optionalHttp1SingletonHeader = runtime.optionalHttp1SingletonHeader;
const decodeHttp2SettingsHeader = runtime.decodeHttp2SettingsHeader;
const flag_ack = runtime.flag_ack;
const writeInitialSettingsTransportMaybeBefore = runtime.writeInitialSettingsTransportMaybeBefore;
const writeInitialConnectionWindowTransportMaybeBefore = runtime.writeInitialConnectionWindowTransportMaybeBefore;
const handshake_protocol_error = @import("connect/protocol_error.zig");
const bootstrap_output = @import("connect/bootstrap_output.zig");
const serveRequestStreamErrorCode = runtime.serveRequestStreamErrorCode;
const responseStreamErrorCode = runtime.responseStreamErrorCode;
const normalizeHandlerResponse = runtime.normalizeHandlerResponse;
const readSome = runtime.readSome;
const writeAllToStream = runtime.writeAllToStream;
const tcpTransport = runtime.tcpTransport;
const connectionHandshakeDeadline = runtime.connectionHandshakeDeadline;
const connectionHandshakeDeadlineBefore = runtime.connectionHandshakeDeadlineBefore;

pub fn acceptOwnedStreamWithDeadline(
    server: anytype,
    stream: net.Stream,
    deadline: std.Io.Clock.Timestamp,
) Error!Connection {
    return @import("connect/owned_accept.zig").accept(server, stream, deadline, @TypeOf(server.*).acceptStreamMaybeBefore);
}

/// Relative-timeout counterpart to `acceptOwnedStreamWithDeadline`. A
/// non-positive duration closes the transferred stream and returns `Timeout`
/// without invoking the handshake.
pub fn acceptOwnedStreamWithTimeout(
    server: anytype,
    stream: net.Stream,
    timeout: std.Io.Duration,
) Error!Connection {
    if (timeout.nanoseconds <= 0) {
        stream.close(server.io);
        return error.Timeout;
    }
    return acceptOwnedStreamWithDeadline(
        server,
        stream,
        .fromNow(server.io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},
    open: bool = true,

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        try validateLocalLimits(limits);
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try bind_address.listen(io, .{ .reuse_address = true }),
            .limits = limits,
        };
    }

    /// Close the listening socket without invalidating the value. Existing
    /// accepted connections remain independent; later accepts fail with
    /// `ConnectionClosed`. `deinit` remains safe after this call.
    pub fn shutdown(self: *Server) void {
        if (!self.open) return;
        self.listener.deinit(self.io);
        self.open = false;
    }

    pub fn deinit(self: *Server) void {
        if (self.open) self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server) Error!Connection {
        if (!self.open) return error.ConnectionClosed;
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream);
    }

    /// Apply one caller-owned deadline to TCP accept and HTTP/2 bootstrap.
    pub fn acceptWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (!self.open) return error.ConnectionClosed;
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamWithDeadline(stream, deadline);
    }

    pub fn acceptWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (!self.open) return error.ConnectionClosed;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamWithDeadline(stream, deadline);
    }

    /// Complete the HTTP/2 server handshake on an already-accepted stream.
    ///
    /// Separating transport acceptance from the handshake lets event loops
    /// dispatch each socket independently: a peer that opens TCP but delays
    /// its connection preface must not prevent the listener from accepting
    /// other peers. Ownership of `stream` transfers to this function.
    pub fn acceptStream(
        self: *Server,
        stream: net.Stream,
    ) Error!Connection {
        return self.acceptStreamMaybeBefore(stream, null);
    }

    pub fn acceptStreamWithDeadline(
        self: *Server,
        stream: net.Stream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    pub fn acceptStreamWithTimeout(
        self: *Server,
        stream: net.Stream,
        timeout: std.Io.Duration,
    ) Error!Connection {
        // Validation precedes ownership transfer, matching the absolute form.
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamWithDeadline(
            stream,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamMaybeBefore(
        self: *Server,
        stream: net.Stream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        // The transport handshake owns cleanup from this point, including
        // failures before it can return a Connection.
        stream_owned = false;
        return acceptConnectionTransportMaybeBefore(
            self.allocator,
            self.io,
            stream,
            tcpTransport(self.io, stream),
            self.limits,
            deadline,
        );
    }

    pub fn acceptUpgrade(self: *Server) Error!H2cUpgradeRequest {
        return self.acceptUpgradeMaybeBefore(null);
    }

    /// Accept an h2c Upgrade under one caller-owned awake-clock deadline. The
    /// budget spans TCP accept, the complete HTTP/1.1 request,
    /// the 101 write, client preface/SETTINGS, and SETTINGS acknowledgement.
    pub fn acceptUpgradeWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2cUpgradeRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptUpgradeMaybeBefore(deadline);
    }

    pub fn acceptUpgradeWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) Error!H2cUpgradeRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptUpgradeWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn acceptUpgradeMaybeBefore(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!H2cUpgradeRequest {
        const stream = if (deadline) |absolute|
            try accept_deadline.withDeadline(&self.listener, self.io, absolute)
        else
            try self.listener.accept(self.io);
        return self.acceptUpgradeStreamMaybeBefore(stream, deadline);
    }

    /// Adopt an already accepted stream for an HTTP/1.1 h2c Upgrade.
    /// Ownership transfers at entry and every failure closes the stream.
    pub fn acceptUpgradeStream(
        self: *Server,
        stream: net.Stream,
    ) Error!H2cUpgradeRequest {
        return self.acceptUpgradeStreamMaybeBefore(stream, null);
    }

    fn acceptUpgradeStreamMaybeBefore(
        self: *Server,
        stream: net.Stream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!H2cUpgradeRequest {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }

        const transport = tcpTransport(self.io, stream);
        const http1_deadline = if (deadline) |absolute|
            try connectionHandshakeDeadlineBefore(
                transport,
                absolute,
                self.limits.handshake_timeout,
            )
        else
            try connectionHandshakeDeadline(
                transport,
                self.limits.handshake_timeout,
            );

        var request = if (http1_deadline) |absolute|
            try http1_runtime.readRequestFromStreamWithDeadline(
                self.allocator,
                self.io,
                stream,
                limitsToHttp1(self.limits),
                .{},
                absolute,
            )
        else
            try http1_runtime.readRequestFromStream(
                self.allocator,
                self.io,
                stream,
                limitsToHttp1(self.limits),
                .{},
            );
        errdefer request.deinit(self.allocator);
        try validateH2cUpgradeRequest(request.request);

        const settings_header = (try optionalHttp1SingletonHeader(request.request.headers, "http2-settings")) orelse return error.InvalidHeader;
        const advertised_settings = try decodeHttp2SettingsHeader(self.allocator, settings_header);
        defer self.allocator.free(advertised_settings);

        const switching_response: http1_runtime.ResponseOptions = .{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = &.{
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Upgrade", .value = "h2c" },
            },
            .request_method = request.request.method,
        };
        if (http1_deadline) |absolute| {
            try http1_runtime.writeResponseToStreamWithDeadline(
                self.allocator,
                self.io,
                stream,
                switching_response,
                absolute,
            );
        } else {
            try http1_runtime.writeResponseToStream(
                self.allocator,
                self.io,
                stream,
                switching_response,
            );
        }

        // Parsing the HTTP/1 request has its own bounded head phase. Once the
        // protocol switch is committed, one new deadline spans every byte of
        // the client preface, its repeated SETTINGS, and its server-SETTINGS
        // acknowledgement. Partial frames cannot turn this into an idle timer.
        const handshake_deadline = if (deadline) |absolute|
            try connectionHandshakeDeadlineBefore(
                transport,
                absolute,
                self.limits.handshake_timeout,
            )
        else
            try connectionHandshakeDeadline(
                transport,
                self.limits.handshake_timeout,
            );
        var preface_buf: [http2.connection_preface.len]u8 = undefined;
        try readExactTransportWithDeadline(
            transport,
            &preface_buf,
            handshake_deadline,
        );
        http2.validateClientPreface(&preface_buf) catch |err| {
            handshake_protocol_error.reject(transport, self.limits, .protocol_error, "invalid-preface", handshake_deadline);
            return err;
        };

        var client_settings = try handshake_protocol_error.readFrame(
            self.allocator,
            transport,
            self.limits,
            handshake_deadline,
        );
        defer client_settings.deinit(self.allocator);
        if (client_settings.frame.header.frame_type != .settings or (client_settings.frame.header.flags & flag_ack) != 0) {
            return error.UnexpectedFrame;
        }
        if (!std.mem.eql(u8, advertised_settings, client_settings.frame.payload)) return error.InvalidFrame;
        const peer_settings = try handshake_protocol_error.parseSettings(
            self.allocator,
            transport,
            self.limits,
            client_settings.frame.payload,
            handshake_deadline,
        );
        defer self.allocator.free(peer_settings);

        try writeInitialSettingsTransportMaybeBefore(
            self.allocator,
            transport,
            self.limits,
            .server,
            handshake_deadline,
        );
        try writeInitialConnectionWindowTransportMaybeBefore(
            self.allocator,
            transport,
            self.limits,
            handshake_deadline,
        );
        try bootstrap_output.writeFrame(
            self.allocator,
            transport,
            .settings,
            flag_ack,
            0,
            &.{},
            handshake_deadline,
        );

        // The HTTP/1 Upgrade request already occupies stream 1, so the next
        // frame the server sees after its SETTINGS is normally the client's
        // SETTINGS ACK rather than HEADERS for stream 1.  Consume it here so
        // applications can immediately answer the upgraded request without
        // leaving unread control bytes that would make a short-lived test/server
        // close look like a TCP reset to the client.
        var client_ack = try handshake_protocol_error.readFrame(
            self.allocator,
            transport,
            self.limits,
            handshake_deadline,
        );
        defer client_ack.deinit(self.allocator);
        if (client_ack.frame.header.frame_type != .settings or (client_ack.frame.header.flags & flag_ack) == 0) {
            return error.UnexpectedFrame;
        }

        var connection = Connection{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .transport = transport,
            .role = .server,
            .limits = self.limits,
            .last_peer_frame_at = std.Io.Clock.awake.now(self.io),
            .awaiting_settings_ack = false,
            .last_peer_client_stream_id = 1,
            .last_peer_processed_stream_id = 1,
        };
        connection.applyLocalLimits();
        errdefer connection.close();
        try connection.applySettings(peer_settings);
        connection.webtransport_settings.acknowledgePeer();
        try connection.reservePeerStream(1);
        errdefer connection.releasePeerStream(1);
        try connection.rememberResponseSemantics(
            1,
            request.request.method.string(),
            null,
            .{},
        );

        stream_owned = false;
        return .{ .connection = connection, .request = request, .stream_id = 1 };
    }

    pub fn serveConnection(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(HandlerContext, context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            Server,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_connections: usize,
        max_requests_per_connection: usize,
        options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            Server,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

/// HTTP/2 prior-knowledge listener over a Unix-domain stream socket.
///
/// This shares the complete HTTP/2 connection state machine with TCP. The
/// filesystem socket path remains caller-owned and is not removed by deinit.
pub const UnixServer = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        limits: Limits,
    ) Error!UnixServer {
        try validateLocalLimits(limits);
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try address.listen(io, .{}),
            .limits = limits,
        };
    }

    pub fn deinit(self: *UnixServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn accept(self: *UnixServer) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return acceptConnectionTransport(
            self.allocator,
            self.io,
            stream,
            tcpTransport(self.io, stream),
            self.limits,
        );
    }

    /// Apply one deadline to Unix accept and the HTTP/2 bootstrap.
    pub fn acceptWithDeadline(
        self: *UnixServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return acceptConnectionTransportMaybeBefore(
            self.allocator,
            self.io,
            stream,
            tcpTransport(self.io, stream),
            self.limits,
            deadline,
        );
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return acceptConnectionTransportMaybeBefore(
            self.allocator,
            self.io,
            stream,
            tcpTransport(self.io, stream),
            self.limits,
            deadline,
        );
    }

    pub fn serveConnection(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(
            HandlerContext,
            context,
            handler,
            max_requests,
        );
    }

    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            UnixServer,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_connections: usize,
        max_requests_per_connection: usize,
        options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            UnixServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

fn acceptConnectionTransport(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    transport: RuntimeTransport,
    limits: Limits,
) Error!Connection {
    return acceptConnectionTransportMaybeBefore(
        allocator,
        io,
        stream,
        transport,
        limits,
        null,
    );
}

/// Adopt an already accepted cleartext stream for prior-knowledge HTTP/2.
/// Ownership transfers at entry and every failure closes the stream.
pub fn adoptPriorKnowledgeStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
) Error!Connection {
    if (limits.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
    return acceptConnectionTransportMaybeBefore(
        allocator,
        io,
        stream,
        tcpTransport(io, stream),
        limits,
        null,
    );
}

/// Adopt an already negotiated TLS server connection for HTTP/2. The caller
/// must have selected ALPN `h2`; ownership transfers at entry on success.
pub fn adoptNegotiatedTlsServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_connection: *tls_stream.ServerConnection,
    limits: Limits,
) Error!Connection {
    if (tls_connection.selected_alpn == null or
        !std.mem.eql(u8, tls_connection.selected_alpn.?, "h2"))
    {
        return error.InvalidAlpn;
    }
    if (limits.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
    return acceptConnectionTransportMaybeBefore(
        allocator,
        io,
        stream,
        .{ .tls_server = tls_connection },
        limits,
        null,
    );
}

fn acceptConnectionTransportMaybeBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    transport: RuntimeTransport,
    limits: Limits,
    outer_deadline: ?std.Io.Clock.Timestamp,
) Error!Connection {
    // Ownership enters with the transport so failures before Connection is
    // constructed (notably a preface timeout) still close TCP or TLS state.
    var transport_owned = true;
    errdefer if (transport_owned) {
        terminal_tls_output.retire(transport);
        transport.close();
    };
    const deadline = if (outer_deadline) |absolute|
        try connectionHandshakeDeadlineBefore(
            transport,
            absolute,
            limits.handshake_timeout,
        )
    else
        try connectionHandshakeDeadline(
            transport,
            limits.handshake_timeout,
        );
    var preface_buf: [http2.connection_preface.len]u8 = undefined;
    try readExactTransportWithDeadline(
        transport,
        &preface_buf,
        deadline,
    );
    http2.validateClientPreface(&preface_buf) catch |err| {
        handshake_protocol_error.reject(transport, limits, .protocol_error, "invalid-preface", deadline);
        return err;
    };

    var client_settings = try handshake_protocol_error.readFrame(
        allocator,
        transport,
        limits,
        deadline,
    );
    defer client_settings.deinit(allocator);
    if (client_settings.frame.header.frame_type != .settings or
        (client_settings.frame.header.flags & flag_ack) != 0)
    {
        return error.UnexpectedFrame;
    }
    const peer_settings = try handshake_protocol_error.parseSettings(
        allocator,
        transport,
        limits,
        client_settings.frame.payload,
        deadline,
    );
    defer allocator.free(peer_settings);

    try writeInitialSettingsTransportMaybeBefore(allocator, transport, limits, .server, deadline);
    try writeInitialConnectionWindowTransportMaybeBefore(allocator, transport, limits, deadline);
    try bootstrap_output.writeFrame(
        allocator,
        transport,
        .settings,
        flag_ack,
        0,
        &.{},
        deadline,
    );

    var connection = Connection{
        .io = io,
        .allocator = allocator,
        .stream = stream,
        .transport = transport,
        .role = .server,
        .limits = limits,
        .last_peer_frame_at = std.Io.Clock.awake.now(io),
        .awaiting_settings_ack = true,
    };
    transport_owned = false;
    errdefer {
        terminal_tls_output.retire(transport);
        connection.close();
    }
    connection.applyLocalLimits();
    try connection.applySettings(peer_settings);
    connection.webtransport_settings.acknowledgePeer();
    return connection;
}

pub const TlsListenOptions = struct {
    identity: vail.tls.auth.ServerIdentity,
    /// Optional late-bound identity source consulted once per handshake.
    /// Supports atomic certificate rotation without rebinding the listener.
    identity_provider: ?tls_stream.ServerIdentityProvider = null,
    limits: Limits = .{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    tls13_session_tickets: ?tls_stream.Tls13ServerTicketPolicy = null,
    tls12_session_tickets: ?tls_stream.Tls12ServerTicketPolicy = null,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute TLS handshake receive budget. HTTP/2 frame waits begin only
    /// after this transport handshake succeeds.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    tcp_nodelay: bool = true,
};

/// Native TLS 1.2/1.3 HTTP/2 listener. ALPN is mandatory and restricted to `h2`,
/// so HTTP/1 traffic can never enter the prior-knowledge HTTP/2 parser.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,
    limits: Limits,
    tls: tls_stream.ServerOptions,
    tcp_nodelay: bool,
    open: bool = true,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) Error!TlsServer {
        try validateLocalLimits(options.limits);
        if (options.identity_provider) |provider| {
            var lease = provider.acquire();
            defer lease.deinit();
            try lease.identity.validate();
        } else {
            try options.identity.validate();
        }
        return .{
            .allocator = allocator,
            .io = io,
            .listener = try bind_address.listen(
                io,
                .{ .reuse_address = true },
            ),
            .limits = options.limits,
            .tls = .{
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
                .alpn_protocols = &.{"h2"},
            },
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

    pub fn accept(self: *TlsServer) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream);
    }

    /// Carry one caller-owned deadline through TCP accept, TLS, and HTTP/2
    /// bootstrap.
    pub fn acceptWithDeadline(
        self: *TlsServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamWithDeadline(stream, deadline);
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (!self.open) return error.ConnectionClosed;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamWithDeadline(stream, deadline);
    }

    /// Complete TLS and HTTP/2 handshakes on an already accepted socket.
    /// Ownership transfers to the returned connection on success.
    pub fn acceptStream(
        self: *TlsServer,
        stream: net.Stream,
    ) Error!Connection {
        return self.acceptStreamMaybeBefore(stream, null);
    }

    pub fn acceptStreamWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    pub fn acceptStreamWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamWithDeadline(
            stream,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
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
        var tls_owned = true;
        errdefer if (tls_owned) {
            const transport = RuntimeTransport{ .tls_server = tls_connection };
            transport.closeWithTerminalBudget(self.io, self.limits);
        };
        if (tls_connection.selected_alpn == null or
            !std.mem.eql(u8, tls_connection.selected_alpn.?, "h2"))
        {
            return error.InvalidAlpn;
        }
        // acceptConnectionTransport owns transport cleanup from this point,
        // including failures before the HTTP/2 Connection exists.
        tls_owned = false;
        return acceptConnectionTransportMaybeBefore(
            self.allocator,
            self.io,
            stream,
            .{ .tls_server = tls_connection },
            self.limits,
            deadline,
        );
    }

    pub fn serveConnection(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(
            HandlerContext,
            context,
            handler,
            max_requests,
        );
    }

    pub fn serveConcurrent(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_connections: usize,
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
        );
    }

    pub fn serveUntil(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        max_connections: usize,
        max_requests_per_connection: usize,
        options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            TlsServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

pub const AsyncServeError = Error || std.Io.Cancelable;

pub const ConcurrentServeResult = struct {
    allocator: std.mem.Allocator,
    errors: []?anyerror,

    pub fn deinit(self: *ConcurrentServeResult) void {
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: ConcurrentServeResult) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn successCount(self: ConcurrentServeResult) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

/// Per-request outcomes from one bounded same-connection concurrent handler
/// batch. A null slot means the response was written successfully. A handler
/// error is recorded after resetting that stream with INTERNAL_ERROR; an
/// accidental final 1xx is recorded as InvalidStatus after writing final 500.
pub const ConcurrentHandlerServeResult = struct {
    allocator: std.mem.Allocator,
    errors: []?anyerror,

    pub fn deinit(self: *ConcurrentHandlerServeResult) void {
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: ConcurrentHandlerServeResult) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn successCount(self: ConcurrentHandlerServeResult) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

pub const ConcurrentHandlerServeError = Error || std.Io.ConcurrentError;

/// RFC 9113 §6.8 processing certainty for a locally initiated request stream.
/// A stream above the peer's GOAWAY Last-Stream-ID is guaranteed not to have
/// been processed and can be retried on a new connection. Streams at or below
/// that boundary may already have application side effects.
pub const GoAwayRetryDisposition = enum {
    no_goaway,
    may_have_been_processed,
    safe_to_retry,
};

pub const ServeErrorStage = enum {
    accept,
    connection,
};

pub const ServeErrorPolicy = enum {
    continue_serving,
    stop,
};

pub const ServeErrorEvent = struct {
    stage: ServeErrorStage,
    err: anyerror,
};

pub const ServeErrorObserver = struct {
    context: *anyopaque,
    /// May be invoked concurrently by independent connection workers.
    observe: *const fn (context: *anyopaque, event: ServeErrorEvent) void,
};

pub const ServeUntilOptions = struct {
    /// Setting this event cancels pending accepts and active frame reads.
    shutdown: *std.Io.Event,
    accept_error_policy: ServeErrorPolicy = .continue_serving,
    connection_error_policy: ServeErrorPolicy = .continue_serving,
    /// Prevent a failed listener from becoming an unbounded retry loop.
    accept_error_backoff: std.Io.Duration = .fromMilliseconds(10),
    error_observer: ?ServeErrorObserver = null,
};

fn serveAcceptedConcurrent(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (
        *HandlerContext,
        OwnedRequest,
    ) Error!ResponseOptions,
    max_connections: usize,
) AsyncServeError!ConcurrentServeResult {
    var group: std.Io.Group = .init;
    const results = try allocator.alloc(?anyerror, max_connections);
    errdefer allocator.free(results);
    @memset(results, null);
    for (results) |*result| {
        var connection = try server.accept();
        errdefer connection.close();
        const task = ServeTask(HandlerContext){
            .connection = connection,
            .context = context,
            .handler = handler,
            .result = result,
        };
        group.async(io, ServeTask(HandlerContext).run, .{task});
    }
    try group.await(io);
    return .{ .allocator = allocator, .errors = results };
}

const ServeSupervisorState = struct {
    io: std.Io,
    options: ServeUntilOptions,
    stopping: std.atomic.Value(bool) = .init(false),
    failed: std.Io.Event = .unset,
    error_mutex: std.Io.Mutex = .init,
    first_error: ?anyerror = null,

    fn shouldStop(self: *@This()) bool {
        return self.stopping.load(.acquire) or self.options.shutdown.isSet();
    }

    fn report(self: *@This(), stage: ServeErrorStage, err: anyerror) void {
        if (self.options.error_observer) |observer| {
            observer.observe(observer.context, .{ .stage = stage, .err = err });
        }
        const policy = switch (stage) {
            .accept => self.options.accept_error_policy,
            .connection => self.options.connection_error_policy,
        };
        if (policy != .stop) return;
        self.error_mutex.lockUncancelable(self.io);
        if (self.first_error == null) self.first_error = err;
        self.error_mutex.unlock(self.io);
        self.stopping.store(true, .release);
        self.failed.set(self.io);
    }

    fn firstError(self: *@This()) ?anyerror {
        self.error_mutex.lockUncancelable(self.io);
        defer self.error_mutex.unlock(self.io);
        return self.first_error;
    }
};

fn serveAcceptedUntil(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (
        *HandlerContext,
        OwnedRequest,
    ) Error!ResponseOptions,
    max_connections: usize,
    max_requests_per_connection: usize,
    options: ServeUntilOptions,
) anyerror!void {
    if (max_connections == 0 or max_requests_per_connection == 0 or
        options.accept_error_backoff.nanoseconds < 0)
    {
        return error.InvalidServeOptions;
    }
    var group: std.Io.Group = .init;
    var supervisor = ServeSupervisorState{ .io = io, .options = options };
    var group_finished = false;
    defer if (!group_finished) {
        supervisor.stopping.store(true, .release);
        group.cancel(io);
    };
    for (0..max_connections) |_| {
        try group.concurrent(
            io,
            ServeUntilTask(ServerType, HandlerContext, handler).run,
            .{ServeUntilTask(ServerType, HandlerContext, handler){
                .supervisor = &supervisor,
                .server = server,
                .context = context,
                .max_requests_per_connection = max_requests_per_connection,
            }},
        );
    }

    const Wake = union(enum) {
        shutdown: std.Io.Cancelable!void,
        failure: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.shutdown, waitForServeEvent, .{ options.shutdown, io });
    try select.concurrent(.failure, waitForServeEvent, .{ &supervisor.failed, io });
    switch (try select.await()) {
        .shutdown => |result| try result,
        .failure => |result| try result,
    }
    supervisor.stopping.store(true, .release);
    group.cancel(io);
    group_finished = true;
    select.cancelDiscard();
    if (supervisor.firstError()) |err| return err;
}

fn ServeUntilTask(
    comptime ServerType: type,
    comptime HandlerContext: type,
    comptime handler: *const fn (
        *HandlerContext,
        OwnedRequest,
    ) Error!ResponseOptions,
) type {
    return struct {
        supervisor: *ServeSupervisorState,
        server: *ServerType,
        context: *HandlerContext,
        max_requests_per_connection: usize,

        fn run(task: @This()) std.Io.Cancelable!void {
            while (!task.supervisor.shouldStop()) {
                var connection = task.server.accept() catch |err| {
                    if (err == error.Canceled or
                        task.supervisor.shouldStop())
                    {
                        return error.Canceled;
                    }
                    task.supervisor.report(.accept, err);
                    if (task.supervisor.shouldStop()) return;
                    const backoff =
                        task.supervisor.options.accept_error_backoff;
                    if (backoff.nanoseconds > 0) {
                        std.Io.sleep(
                            task.supervisor.io,
                            backoff,
                            .awake,
                        ) catch |sleep_err| switch (sleep_err) {
                            error.Canceled => return error.Canceled,
                        };
                    }
                    continue;
                };
                defer connection.close();
                _ = connection.serve(
                    HandlerContext,
                    task.context,
                    handler,
                    task.max_requests_per_connection,
                ) catch |err| {
                    if (err == error.Canceled and
                        task.supervisor.shouldStop()) return;
                    task.supervisor.report(.connection, err);
                };
            }
        }
    };
}

fn waitForServeEvent(
    event: *std.Io.Event,
    io: std.Io,
) std.Io.Cancelable!void {
    try event.wait(io);
}

fn ServeTask(comptime HandlerContext: type) type {
    return struct {
        connection: Connection,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();

            connection.serve_read_connection_error = null;
            connection.serve_read_stream_error = null;
            var request = connection.readRequest() catch |err| {
                connection.sendServeReadError(err);
                task.result.* = err;
                return;
            };
            defer request.deinit(connection.allocator);

            var response = task.handler(task.context, request) catch |err| {
                task.result.* = err;
                return;
            };
            const invalid_final = normalizeHandlerResponse(
                &response,
                request.method,
                request.protocol != null,
            );
            connection.writeResponse(request.stream_id, response) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = if (invalid_final) error.InvalidStatus else null;
        }
    };
}

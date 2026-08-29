const std = @import("std");
const builtin = @import("builtin");
const websocket = @import("mod.zig");
const common = @import("runtime/common.zig");
const http1 = @import("../http1/mod.zig");
const http2 = @import("../http2/mod.zig");
const http1_runtime = http1.runtime;
const http2_runtime = http2.runtime;
const tls_stream = @import("../tls/mod.zig").stream;
const tls_client_identity = @import(
    "runtime/tls_client_identity.zig",
);
const compression_scratch =
    @import("runtime/compression_scratch.zig");
const origin_policy = @import("runtime/origin_policy.zig");
const stream_io = @import("../internal/stream_io.zig");
const deadline_policy = @import("../internal/deadline.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const socket_options = @import("../internal/socket_options.zig");
const wire = @import("../internal/wire.zig");
const vail = @import("vail");

const net = std.Io.net;

pub const h3 = @import("runtime/h3.zig");
/// Default lower bound for attempting permessage-deflate. Raw DEFLATE framing
/// cannot profitably encode very small messages, and initializing compressor
/// state would dominate their latency. Callers may tune this per endpoint.
pub const default_compression_threshold: usize = 32;
const masked_write_scratch_len: usize = 16 * 1024;
// A 4 KiB application payload occupies 4104 bytes on the masked wire. The old
// 4096-byte read scratch therefore forced two socket reads for this common
// frame size. Keep the burst on the call stack (rather than 16 KiB resident per
// connection) while covering typical WebSocket/TLS records in one read.
const transport_read_scratch_len: usize = 16 * 1024;

pub const Error = websocket.Error || http1_runtime.Error ||
    http2_runtime.Error || tls_stream.Error || error{
    HeadersTooLarge,
    ConnectionClosed,
    InvalidResponse,
    InvalidOrigin,
    InvalidSubprotocol,
    InvalidUri,
    UnsupportedScheme,
    MessageTooLarge,
    UnexpectedPong,
    InvalidServeOptions,
    TimedReadUnsupported,
    ExporterUnavailable,
    TlsKeyUpdateUnavailable,
} || std.Io.RandomSecureError || net.HostName.ValidateError || net.HostName.ConnectError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.posix.SetSockOptError;

pub const Limits = common.Limits;
pub const Role = common.Role;

const IncomingDataKind = enum {
    none,
    binary,
    text,
    compressed_text,
};

pub const ClientIdentity = tls_client_identity.ClientIdentity;
pub const ClientCertificateVerifier =
    tls_client_identity.CertificateVerifier;

const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls: *http1_runtime.TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,
    linux_io_uring: http1_runtime.LinuxIoUringStream,

    fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls => |conn| conn.read(buffer),
            .tls_vail => |conn| conn.read(buffer),
            .tls_server => |conn| conn.read(buffer),
            .linux_io_uring => |conn| conn.read(buffer),
        };
    }

    /// Read transport bytes without moving an application-owned absolute
    /// deadline. Buffered TLS plaintext is still returned immediately; only a
    /// read that reaches the socket waits against `deadline`.
    fn readWithDeadline(
        self: RuntimeTransport,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSomeWithDeadline(
                tcp.io,
                tcp.stream,
                buffer,
                deadline,
            ),
            .tls_vail => |conn| conn.readWithDeadline(buffer, deadline),
            .tls_server => |conn| conn.readWithDeadline(buffer, deadline),
            .tls => |conn| conn.readWithDeadline(buffer, deadline),
            // The raw io_uring adapter does not expose deadline-aware reads.
            // Failing explicitly is safer than silently weakening an
            // upper-layer inactivity contract.
            .linux_io_uring => error.TimedReadUnsupported,
        };
    }

    fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
            .linux_io_uring => |conn| conn.writeAll(bytes),
        };
    }

    fn writeAllParts(
        self: RuntimeTransport,
        header: []const u8,
        payload: []const u8,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllParts(
                tcp.io,
                tcp.stream,
                header,
                payload,
            ),
            .tls => |conn| conn.writeAllParts(header, payload),
            .tls_vail => |conn| conn.writeAllParts(header, payload),
            .tls_server => |conn| conn.writeAllParts(header, payload),
            // The raw io_uring adapter currently exposes one-slice sends.
            // Two submissions still avoid a payload-sized temporary copy.
            .linux_io_uring => |conn| {
                try conn.writeAll(header);
                try conn.writeAll(payload);
            },
        };
    }

    fn writeAllSlices(
        self: RuntimeTransport,
        parts: []const []const u8,
    ) Error!void {
        switch (self) {
            .tcp => |tcp| return stream_io.writeAllSlices(
                tcp.io,
                tcp.stream,
                parts,
            ),
            .tls => |conn| return conn.writeAllSlices(parts),
            .tls_vail, .tls_server, .linux_io_uring => {
                for (parts) |part| try self.writeAll(part);
            },
        }
    }

    fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls => |conn| conn.deinit(),
            .tls_vail => |conn| conn.deinit(),
            .tls_server => |conn| conn.deinit(),
            .linux_io_uring => |conn| conn.close(),
        }
    }
};

pub const Server = struct {
    http: http1_runtime.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .http = try .listen(allocator, io, bind_address, .{
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
        const http_conn = try self.http.accept();
        return self.acceptHttpConnection(http_conn, options);
    }

    /// Accept TCP, then bound the complete HTTP Upgrade with one caller-owned
    /// awake-clock deadline. The listener accept itself remains unbounded.
    pub fn acceptWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        const http_conn = try self.http.accept();
        return self.acceptHttpConnectionWithDeadline(
            http_conn,
            options,
            deadline,
        );
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const http_conn = try self.http.accept();
        return self.acceptHttpConnectionWithDeadline(
            http_conn,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Upgrade an already accepted HTTP/1 connection. This lets protocol
    /// adapters consume a trusted preface without duplicating WebSocket
    /// handshake validation.
    pub fn acceptHttpConnection(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!Connection {
        return self.acceptHttpConnectionMaybeBefore(
            http_connection,
            options,
            null,
        );
    }

    /// Upgrade an accepted HTTP/1 connection before an absolute deadline. The
    /// connection transfers at entry and is closed on every failure path.
    pub fn acceptHttpConnectionWithDeadline(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.acceptHttpConnectionMaybeBefore(
            http_connection,
            options,
            deadline,
        );
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

    fn acceptHttpConnectionMaybeBefore(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var http_conn = http_connection;
        errdefer http_conn.close();
        if (self.limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(http_conn.stream);
        }

        return acceptTransport(
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
        return self.acceptMaybeBefore(options, null);
    }

    /// Accept a Unix stream, then bound its HTTP Upgrade with one caller-owned
    /// awake-clock deadline. Socket acceptance itself remains unbounded.
    pub fn acceptWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.acceptMaybeBefore(options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const http_connection = try self.http.accept();
        return self.upgradeHttpConnectionMaybeBefore(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptMaybeBefore(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        const http_connection = try self.http.accept();
        return self.upgradeHttpConnectionMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    fn upgradeHttpConnectionMaybeBefore(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var http_connection_owned = http_connection;
        var http_owned = true;
        errdefer if (http_owned) http_connection_owned.close();
        var limits = self.limits;
        limits.tcp_nodelay = false;
        const connection = try acceptTransport(
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
        return connection;
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
        try options.identity.validate();
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
                .cipher_suites = options.cipher_suites,
                .max_client_hello_size = options.max_client_hello_size,
                .max_client_handshake_size = options.max_client_handshake_size,
                .handshake_timeout = options.tls_handshake_timeout,
                .client_auth = options.client_auth,
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

    pub fn accept(
        self: *TlsServer,
        options: AcceptOptions,
    ) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream, options);
    }

    /// Accept TCP, then carry one caller-owned deadline through TLS and the
    /// HTTP Upgrade. The listener accept itself remains unbounded.
    pub fn acceptWithDeadline(
        self: *TlsServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamWithDeadline(stream, options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Perform TLS and WebSocket handshakes on an already accepted stream.
    pub fn acceptStream(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!Connection {
        return self.acceptStreamMaybeBefore(stream, options, null);
    }

    pub fn acceptStreamWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamMaybeBefore(stream, options, deadline);
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

    fn acceptStreamMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
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
        errdefer tls_connection.deinit();
        return acceptTransport(
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

pub const TlsListenOptions = struct {
    identity: vail.tls.auth.ServerIdentity,
    limits: Limits = .{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute TLS handshake receive budget. The WebSocket Upgrade-head
    /// deadline starts independently after TLS succeeds.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    tcp_nodelay: bool = true,
};

fn acceptTransport(
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: RuntimeTransport,
    limits: Limits,
    options: AcceptOptions,
    outer_deadline: ?std.Io.Clock.Timestamp,
) Error!Connection {
    const deadline = deadline_policy.earlier(
        outer_deadline,
        if (limits.http1_handshake_timeout) |timeout|
            try handshakeDeadline(transport, timeout)
        else
            null,
    );
    var head = try readHttpHeadFromTransport(
        allocator,
        transport,
        limits.max_head_bytes,
        deadline,
    );
    defer head.deinit(allocator);

    var request = try http1.parseRequest(allocator, head.head, .{});
    defer request.deinit(allocator);
    try websocket.validateClientHandshake(request);
    try origin_policy.validateHttp1(request.headers, options.allowed_origins);
    // Bytes sent before the 101 response are ambiguous HTTP smuggling/junk,
    // regardless of whether the carrier is TCP or TLS.
    if (head.extra.len != 0) return error.InvalidHandshake;

    const key = request.header("sec-websocket-key") orelse
        return error.MissingHeader;
    const selected_protocol = try selectHttp1Subprotocol(
        allocator,
        request.headers,
        options.protocols,
    );
    errdefer if (selected_protocol) |protocol| allocator.free(protocol);
    if (options.require_subprotocol and selected_protocol == null) {
        return error.InvalidSubprotocol;
    }
    const selected_extension =
        try websocket.ExtensionNegotiation.acceptClientHeaders(
            allocator,
            request.headers,
            options.enable_permessage_deflate,
        );
    defer if (selected_extension) |extension| allocator.free(extension);
    const negotiated_extension = if (selected_extension) |extension|
        try websocket.ExtensionNegotiation.validateResponse(extension)
    else
        websocket.ExtensionNegotiation{};

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    if (selected_protocol) |protocol| {
        try headers.append(allocator, .{
            .name = "Sec-WebSocket-Protocol",
            .value = protocol,
        });
    }
    if (selected_extension) |extension| {
        try headers.append(allocator, .{
            .name = "Sec-WebSocket-Extensions",
            .value = extension,
        });
    }
    try headers.appendSlice(allocator, options.extra_headers);
    try websocket.writeServerHandshake(
        &response,
        allocator,
        key,
        headers.items,
    );
    try transport.writeAll(response.items);

    return .{
        .io = io,
        .allocator = allocator,
        .stream = switch (transport) {
            .tcp => |tcp| tcp.stream,
            .tls_server => |connection| connection.stream,
            .tls => |connection| connection.stream,
            .tls_vail => |connection| connection.stream,
            .linux_io_uring => undefined,
        },
        .tls_server_conn = switch (transport) {
            .tls_server => |connection| connection,
            else => null,
        },
        .role = .server,
        .limits = limits,
        .selected_protocol = selected_protocol,
        .permessage_deflate = negotiated_extension.permessage_deflate,
        .compression_threshold = options.compression_threshold,
        .compression_send_max_window_bits = negotiated_extension.server_max_window_bits orelse 15,
    };
}

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
    /// May be called concurrently by independent connection workers.
    observe: *const fn (context: *anyopaque, event: ServeErrorEvent) void,
};

pub const ServeUntilOptions = struct {
    /// Setting this event cancels blocked accepts and active handler I/O.
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
    comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
    max_connections: usize,
    options: AcceptOptions,
) AsyncServeError!ConcurrentServeResult {
    var group: std.Io.Group = .init;
    const results = try allocator.alloc(?anyerror, max_connections);
    errdefer allocator.free(results);
    @memset(results, null);

    for (results) |*result| {
        var connection = try server.accept(options);
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
    comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
    max_connections: usize,
    accept_options: AcceptOptions,
    options: ServeUntilOptions,
) anyerror!void {
    if (max_connections == 0 or
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
            ServeUntilTask(ServerType, HandlerContext).run,
            .{ServeUntilTask(ServerType, HandlerContext){
                .supervisor = &supervisor,
                .server = server,
                .context = context,
                .handler = handler,
                .accept_options = accept_options,
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
) type {
    return struct {
        supervisor: *ServeSupervisorState,
        server: *ServerType,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, *Connection) Error!void,
        accept_options: AcceptOptions,

        fn run(task: @This()) std.Io.Cancelable!void {
            while (!task.supervisor.shouldStop()) {
                var connection = task.server.accept(
                    task.accept_options,
                ) catch |err| {
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
                task.handler(task.context, &connection) catch |err| {
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

fn appendTransportBytesPrecise(
    buffer: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    const required = std.math.add(
        usize,
        buffer.items.len,
        bytes.len,
    ) catch return error.OutOfMemory;
    if (required > buffer.capacity) {
        // Socket reads frequently split one frame into a tiny header prefix and
        // a payload suffix. Exact growth for each piece minimizes retained
        // memory but needlessly reallocates twice. Round only within a bounded
        // 256-byte slab: common small continuations reuse capacity while a 4
        // KiB frame retains at most 255 bytes of slack rather than ArrayList's
        // roughly 1.5x geometric over-allocation.
        const slab: usize = 256;
        const rounded = std.mem.alignForward(usize, required, slab);
        try buffer.ensureTotalCapacityPrecise(allocator, rounded);
    }
    buffer.appendSliceAssumeCapacity(bytes);
}

fn ServeTask(comptime HandlerContext: type) type {
    return struct {
        connection: Connection,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, *Connection) Error!void,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();
            task.handler(task.context, &connection) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    /// Reject the HTTP upgrade unless one of `protocols` was selected.
    ///
    /// Generic WebSocket servers often allow clients to omit a subprotocol,
    /// while protocol bindings such as MQTT require the opening handshake to
    /// select their registered token. Keeping this opt-in avoids weakening the
    /// generic behavior while allowing adapters to fail before sending 101.
    require_subprotocol: bool = false,
    /// When non-empty, require exactly one Origin header whose complete value
    /// byte-for-byte matches an entry. An empty list preserves non-browser and
    /// same-origin-agnostic server use cases by disabling Origin enforcement.
    allowed_origins: []const []const u8 = &.{},
    extra_headers: []const http1.Header = &.{},
    enable_permessage_deflate: bool = false,
    /// Minimum complete message size considered for outbound compression.
    /// Inbound compressed messages remain accepted after negotiation.
    compression_threshold: usize = default_compression_threshold,
};

pub const TlsClientIdentityOptions = tls_client_identity.Options;

pub const Client = struct {
    /// Perform a cleartext WebSocket handshake on an already connected stream.
    /// This is primarily for adapters that must emit a transport preface before
    /// the HTTP Upgrade request. Ownership transfers on success.
    pub fn connectAcceptedStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const connection = try connectStream(
            allocator,
            io,
            stream,
            null,
            options,
        );
        stream_owned = false;
        return connection;
    }

    /// Perform TLS and WebSocket handshakes on a connected stream after an
    /// adapter has emitted a transport preface such as PROXY protocol.
    pub fn connectAcceptedTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (options.vail_tls orelse options.tls_identity) |identity| {
            const tls_conn = try tls_client_identity.init(
                allocator,
                io,
                stream,
                server_name,
                tls_options,
                identity,
            );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return connectVailStream(
                allocator,
                io,
                stream,
                tls_conn,
                options,
            );
        }
        const tls_conn = try http1_runtime.TlsClientConnection.init(
            allocator,
            io,
            stream,
            server_name,
            tls_options,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        return connectStream(allocator, io, stream, tls_conn, options);
    }

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try tcp_connect.ip(io, address, options.connect_timeout);
        errdefer stream.close(io);
        return connectStream(allocator, io, stream, null, options);
    }

    /// Establish cleartext WebSocket under one caller-owned deadline spanning
    /// TCP setup and the complete HTTP Upgrade response.
    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        return connectStreamBefore(
            allocator,
            io,
            stream,
            null,
            options,
            deadline,
        );
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect a cleartext WebSocket over a Unix-domain stream socket.
    /// `options.host` remains the HTTP Host authority and must be supplied by
    /// the caller because a filesystem path is not an HTTP authority.
    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        if (options.host.len == 0) return error.InvalidUri;
        const stream = try tcp_connect.unix(io, address, options.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connect_options = options;
        connect_options.tcp_nodelay = false;
        const connection = try connectStream(
            allocator,
            io,
            stream,
            null,
            connect_options,
        );
        stream_owned = false;
        return connection;
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        if (options.host.len == 0) return error.InvalidUri;
        const stream = try tcp_connect.unixWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connect_options = options;
        connect_options.tcp_nodelay = false;
        const connection = try connectStreamBefore(
            allocator,
            io,
            stream,
            null,
            connect_options,
            deadline,
        );
        stream_owned = false;
        return connection;
    }

    pub fn connectUnixWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(
            io,
            host_name,
            port,
            options.connect_timeout,
        );
        errdefer stream.close(io);
        const default_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        return connectStream(allocator, io, stream, null, connect_options);
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        const default_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ host, port },
        );
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        return connectStreamBefore(
            allocator,
            io,
            stream,
            null,
            connect_options,
            deadline,
        );
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
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

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(
            io,
            host_name,
            port,
            options.connect_timeout,
        );
        return connectTlsStream(
            allocator,
            io,
            stream,
            host,
            port,
            options,
            tls_options,
        );
    }

    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        return connectTlsStreamBefore(
            allocator,
            io,
            stream,
            host,
            port,
            options,
            tls_options,
            deadline,
        );
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect to a resolved address while verifying TLS against a separate
    /// hostname. This keeps caller-controlled DNS/service discovery distinct
    /// from SNI and certificate identity. `options.host`, when empty, defaults
    /// to `tls_host:address-port` for the HTTP Upgrade authority.
    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        _ = try net.HostName.init(tls_host);
        const stream = try tcp_connect.ip(
            io,
            address,
            options.connect_timeout,
        );
        return connectTlsStream(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            options,
            tls_options,
        );
    }

    pub fn connectTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try net.HostName.init(tls_host);
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        return connectTlsStreamBefore(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            options,
            tls_options,
            deadline,
        );
    }

    pub fn connectTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Own `stream` from entry and close it on every pre-connection failure.
    /// Both hostname and pre-resolved-address APIs use this path so standard
    /// TLS, vail TLS, Host synthesis, and socket policy cannot drift apart.
    fn connectTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        return connectTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            options,
            tls_options,
            null,
        );
    }

    fn connectTlsStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            options,
            tls_options,
            deadline,
        );
    }

    fn connectTlsStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const default_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ tls_host, port },
        );
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) {
            connect_options.host = default_host;
        }
        if (connect_options.vail_tls orelse
            connect_options.tls_identity) |identity|
        {
            const tls_conn = if (deadline) |absolute|
                try tls_client_identity.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    tls_host,
                    tls_options,
                    identity,
                    absolute,
                )
            else
                try tls_client_identity.init(
                    allocator,
                    io,
                    stream,
                    tls_host,
                    tls_options,
                    identity,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return if (deadline) |absolute|
                connectVailStreamBefore(
                    allocator,
                    io,
                    stream,
                    tls_conn,
                    connect_options,
                    absolute,
                )
            else
                connectVailStream(
                    allocator,
                    io,
                    stream,
                    tls_conn,
                    connect_options,
                );
        }
        const tls_conn = if (deadline) |absolute|
            try http1_runtime.TlsClientConnection.initWithDeadline(
                allocator,
                io,
                stream,
                tls_host,
                tls_options,
                absolute,
            )
        else
            try http1_runtime.TlsClientConnection.init(
                allocator,
                io,
                stream,
                tls_host,
                tls_options,
            );
        stream_owned = false;
        errdefer tls_conn.deinit();
        return if (deadline) |absolute|
            connectStreamBefore(
                allocator,
                io,
                stream,
                tls_conn,
                connect_options,
                absolute,
            )
        else
            connectStream(allocator, io, stream, tls_conn, connect_options);
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!Connection {
        return connectUriTls(allocator, io, uri_text, options, .{});
    }

    pub fn connectUriTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        return connectUriTlsBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            null,
        );
    }

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .{},
            deadline,
        );
    }

    pub fn connectUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectUriTlsBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn connectUriTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriTlsBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_ws = std.ascii.eqlIgnoreCase(uri.scheme, "ws");
        const is_wss = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!is_ws and !is_wss) return error.UnsupportedScheme;
        if ((options.tls_identity != null or options.vail_tls != null) and
            !is_wss)
        {
            // Client certificates are TLS credentials. Reject rather than
            // silently dropping them when this helper receives a ws:// URI.
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, if (is_wss) 443 else 80);
        defer endpoint.deinit();

        var connect_options = options;
        connect_options.target = target;
        if (connect_options.host.len == 0) connect_options.host = endpoint.authority;

        const stream = if (deadline) |absolute| switch (endpoint.target) {
            .host => |host| try tcp_connect.hostWithDeadline(
                io,
                host,
                endpoint.port,
                try deadline_policy.capTimeout(
                    io,
                    absolute,
                    options.connect_timeout,
                ),
            ),
            .ip => |address| try tcp_connect.ipWithDeadline(
                io,
                address,
                try deadline_policy.capTimeout(
                    io,
                    absolute,
                    options.connect_timeout,
                ),
            ),
        } else switch (endpoint.target) {
            .host => |host| try tcp_connect.host(
                io,
                host,
                endpoint.port,
                options.connect_timeout,
            ),
            .ip => |address| try tcp_connect.ip(
                io,
                address,
                options.connect_timeout,
            ),
        };
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (is_wss) {
            if (options.vail_tls orelse options.tls_identity) |identity| {
                const tls_conn = if (deadline) |absolute|
                    try tls_client_identity.initWithDeadline(
                        allocator,
                        io,
                        stream,
                        endpoint.tls_host,
                        tls_options,
                        identity,
                        absolute,
                    )
                else
                    try tls_client_identity.init(
                        allocator,
                        io,
                        stream,
                        endpoint.tls_host,
                        tls_options,
                        identity,
                    );
                stream_owned = false;
                errdefer tls_conn.deinit();
                return if (deadline) |absolute|
                    connectVailStreamBefore(
                        allocator,
                        io,
                        stream,
                        tls_conn,
                        connect_options,
                        absolute,
                    )
                else
                    connectVailStream(
                        allocator,
                        io,
                        stream,
                        tls_conn,
                        connect_options,
                    );
            }
            var standard_tls_options = tls_options;
            if (standard_tls_options.handshake_timeout == null) {
                standard_tls_options.handshake_timeout =
                    connect_options.tls_handshake_timeout;
            }
            const tls_conn = if (deadline) |absolute|
                try http1_runtime.TlsClientConnection.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    standard_tls_options,
                    absolute,
                )
            else
                try http1_runtime.TlsClientConnection.init(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    standard_tls_options,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return if (deadline) |absolute|
                connectStreamBefore(
                    allocator,
                    io,
                    stream,
                    tls_conn,
                    connect_options,
                    absolute,
                )
            else
                connectStream(
                    allocator,
                    io,
                    stream,
                    tls_conn,
                    connect_options,
                );
        }
        const connection = if (deadline) |absolute|
            try connectStreamBefore(
                allocator,
                io,
                stream,
                null,
                connect_options,
                absolute,
            )
        else
            try connectStream(
                allocator,
                io,
                stream,
                null,
                connect_options,
            );
        stream_owned = false;
        return connection;
    }

    /// Linux-only `ws://` client path backed by `std.os.linux.IoUring`.
    ///
    /// This mirrors the HTTP/1 io_uring client support and reuses the same
    /// WebSocket handshake/framing logic as the normal TCP runtime.  It is
    /// limited to cleartext `ws://` and literal IP authorities because TLS and
    /// DNS still depend on the higher-level `std.Io.net`/TLS layers.
    pub fn connectUriLinuxIoUring(
        allocator: std.mem.Allocator,
        io: std.Io,
        ring: *http1_runtime.LinuxIoUringHandle,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!Connection {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "ws")) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, 80);
        defer endpoint.deinit();
        const address = switch (endpoint.target) {
            .ip => |address| address,
            .host => return error.UnsupportedEndpoint,
        };

        var connect_options = options;
        connect_options.target = target;
        if (connect_options.host.len == 0) connect_options.host = endpoint.authority;

        var uring_stream = try http1_runtime.connectIpLinuxIoUring(ring, address);
        errdefer uring_stream.close();
        if (connect_options.tcp_nodelay) {
            try setLinuxTcpNoDelay(uring_stream.fd);
        }
        return connectTransport(
            allocator,
            io,
            .{ .linux_io_uring = uring_stream },
            undefined,
            null,
            null,
            uring_stream,
            connect_options,
            null,
        );
    }

    fn connectStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
    ) Error!Connection {
        return connectStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            null,
        );
    }

    fn connectStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            deadline,
        );
    }

    fn connectStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (options.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        const transport: RuntimeTransport = if (tls_conn) |conn| .{ .tls = conn } else .{ .tcp = .{ .io = io, .stream = stream } };
        return connectTransport(
            allocator,
            io,
            transport,
            stream,
            tls_conn,
            null,
            null,
            options,
            deadline,
        );
    }

    fn connectVailStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: *tls_stream.ClientConnection,
        options: ConnectOptions,
    ) Error!Connection {
        return connectVailStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            null,
        );
    }

    fn connectVailStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: *tls_stream.ClientConnection,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectVailStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            deadline,
        );
    }

    fn connectVailStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: *tls_stream.ClientConnection,
        options: ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (options.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        return connectTransport(
            allocator,
            io,
            .{ .tls_vail = tls_conn },
            stream,
            null,
            tls_conn,
            null,
            options,
            deadline,
        );
    }

    fn connectTransport(
        allocator: std.mem.Allocator,
        io: std.Io,
        transport: RuntimeTransport,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        tls_vail_conn: ?*tls_stream.ClientConnection,
        linux_io_uring: ?http1_runtime.LinuxIoUringStream,
        options: ConnectOptions,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var nonce: [16]u8 = undefined;
        try std.Io.randomSecure(io, &nonce);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &nonce);

        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(allocator);
        try headers.appendSlice(allocator, &.{
            .{ .name = "Upgrade", .value = "websocket" },
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Sec-WebSocket-Key", .value = &key },
            .{ .name = "Sec-WebSocket-Version", .value = "13" },
        });
        var protocol_value: std.ArrayList(u8) = .empty;
        defer protocol_value.deinit(allocator);
        if (options.protocols.len != 0) {
            for (options.protocols, 0..) |protocol, index| {
                if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
                if (index != 0) try protocol_value.appendSlice(allocator, ", ");
                try protocol_value.appendSlice(allocator, protocol);
            }
            try headers.append(allocator, .{ .name = "Sec-WebSocket-Protocol", .value = protocol_value.items });
        }
        if (options.origin) |origin| {
            try headers.append(allocator, .{
                .name = "Origin",
                .value = origin,
            });
        }
        if (options.enable_permessage_deflate) {
            try headers.append(allocator, .{
                .name = "Sec-WebSocket-Extensions",
                .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            });
        }
        try writeHttpUpgradeRequest(allocator, transport, .{
            .method = .GET,
            .target = options.target,
            .host = options.host,
            .headers = headers.items,
        });

        const deadline = deadline_policy.earlier(
            outer_deadline,
            if (options.limits.http1_handshake_timeout) |timeout|
                try handshakeDeadline(transport, timeout)
            else
                null,
        );
        var head = try readHttpHeadFromTransport(
            allocator,
            transport,
            options.limits.max_head_bytes,
            deadline,
        );
        defer head.deinit(allocator);
        var response = try http1.parseResponse(allocator, head.head, .{});
        defer response.deinit(allocator);
        if (response.status != 101) return error.InvalidResponse;
        const selected_protocol = try validateServerHandshake(allocator, response, &key, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        const selected_extension = try websocket.ExtensionNegotiation.validateResponse(try optionalSingletonHeader(response.headers, "sec-websocket-extensions"));
        if (selected_extension.permessage_deflate and !options.enable_permessage_deflate) return error.InvalidExtension;

        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .tls_conn = tls_conn,
            .tls_vail_conn = tls_vail_conn,
            .linux_io_uring = linux_io_uring,
            .role = .client,
            .limits = options.limits,
            .selected_protocol = selected_protocol,
            .permessage_deflate = selected_extension.permessage_deflate,
            .compression_threshold = options.compression_threshold,
            .compression_send_max_window_bits = selected_extension.client_max_window_bits orelse 15,
            .inbuf = try std.ArrayList(u8).initCapacity(allocator, head.extra.len),
        };
        errdefer connection.inbuf.deinit(connection.allocator);
        try connection.bufferInitial(head.extra);
        return connection;
    }
};

fn uriTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const path_value = uriComponentBytes(uri.path);
    const path = if (path_value.len == 0) "/" else path_value;
    if (uri.query) |query| {
        return try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, uriComponentBytes(query) });
    }
    return try allocator.dupe(u8, path);
}

fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

pub const ConnectOptions = struct {
    /// HTTP Host authority for the WebSocket opening handshake.  `connectHost`
    /// defaults this to its resolved host name when left empty.
    host: []const u8 = "",
    target: []const u8 = "/",
    protocols: []const []const u8 = &.{},
    /// Optional browser Origin value for the opening request.
    origin: ?[]const u8 = null,
    enable_permessage_deflate: bool = false,
    /// Minimum complete message size considered for outbound compression.
    /// Set to zero to attempt every data message or maxInt to receive-only.
    compression_threshold: usize = default_compression_threshold,
    tcp_nodelay: bool = true,
    /// Absolute budget for DNS resolution plus all TCP connection attempts.
    /// TLS and HTTP Upgrade retain their separate handshake policies.
    connect_timeout: ?std.Io.Duration = null,
    limits: Limits = .{},
    /// Backward-compatible mTLS shorthand. `vail_tls` takes precedence when
    /// both are supplied.
    tls_identity: ?TlsClientIdentityOptions = null,
    /// Select vail-backed WSS without requiring a client certificate. This
    /// enables peer-chain, ALPN, exporter and KeyUpdate APIs for ordinary WSS.
    /// Cleartext connect helpers reject this field.
    vail_tls: ?TlsClientIdentityOptions = null,
    /// Optional TLS handshake budget used by the standard WSS client. The
    /// vail path uses this value when its nested option leaves one unset.
    tls_handshake_timeout: ?std.Io.Duration = null,
};

pub const OwnedMessage = common.OwnedMessage;

/// One observable step while completing a locally initiated close handshake.
/// Application frames may already be in flight when Close is sent, so they are
/// returned with ownership rather than discarded by the shutdown helper.
pub const CloseHandshakeEvent = union(enum) {
    closed: ?websocket.OwnedCloseFrame,
    application: websocket.Frame,

    pub fn deinit(
        self: *CloseHandshakeEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .closed => |maybe_close| if (maybe_close) |value| {
                var close_frame = value;
                close_frame.deinit(allocator);
            },
            .application => |value| {
                var frame = value;
                frame.deinit(allocator);
            },
        }
        self.* = undefined;
    }
};

/// One observable step while awaiting the Pong for a locally sent Ping.
/// Application and Close frames are returned rather than consumed invisibly.
pub const PingEvent = union(enum) {
    pong: void,
    closed: ?websocket.OwnedCloseFrame,
    application: websocket.Frame,

    pub fn deinit(self: *PingEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .pong => {},
            .closed => |maybe_close| if (maybe_close) |value| {
                var close_frame = value;
                close_frame.deinit(allocator);
            },
            .application => |value| {
                var frame = value;
                frame.deinit(allocator);
            },
        }
        self.* = undefined;
    }
};

pub const Message = struct {
    opcode: websocket.Opcode,
    payload: []u8,
};

/// Resumable state for the caller-buffer receive path. The caller owns the
/// bytes already written, so retries after a timeout must present the same
/// storage until the fragmented message completes.
const MessageIntoReceiveState = struct {
    opcode: ?websocket.Opcode = null,
    compressed: bool = false,
    written: usize = 0,
    output_address: usize = 0,
    output_len: usize = 0,

    fn active(self: MessageIntoReceiveState) bool {
        return self.opcode != null;
    }

    fn begin(
        self: *MessageIntoReceiveState,
        out: []u8,
        opcode: websocket.Opcode,
        compressed: bool,
    ) void {
        self.* = .{
            .opcode = opcode,
            .compressed = compressed,
            .output_address = @intFromPtr(out.ptr),
            .output_len = out.len,
        };
    }

    fn validateOutput(
        self: MessageIntoReceiveState,
        out: []u8,
    ) Error!void {
        if (!self.active()) return;
        if (self.output_address != @intFromPtr(out.ptr) or
            self.output_len != out.len)
        {
            return error.BufferTooShort;
        }
    }

    fn reset(self: *MessageIntoReceiveState) void {
        self.* = .{};
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    tls_conn: ?*http1_runtime.TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    tls_server_conn: ?*tls_stream.ServerConnection = null,
    linux_io_uring: ?http1_runtime.LinuxIoUringStream = null,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    send_mutex: std.Io.Mutex = .init,
    close_sent: bool = false,
    close_received: bool = false,
    incoming_data_kind: IncomingDataKind = .none,
    incoming_text_utf8: websocket.Utf8Validator = .{},
    incoming_frame_validated: usize = 0,
    message_assembler: ?websocket.MessageAssembler = null,
    message_into: MessageIntoReceiveState = .{},
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,
    compression_threshold: usize = default_compression_threshold,
    /// Maximum LZ77 distance for messages emitted by this endpoint. The field
    /// follows the role-specific RFC 7692 direction selected at handshake.
    compression_send_max_window_bits: u8 = 15,
    compression_send: compression_scratch.SendScratch = .{},
    compression_receive: compression_scratch.Scratch = .{},

    /// Return the authenticated peer certificate chain. Server-side WSS
    /// returns a verified client chain when mTLS succeeded; vail-backed WSS
    /// clients return the verified server chain. Other transports return null.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        if (self.tls_server_conn) |connection| {
            return connection.peerCertificates();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.peerCertificates();
        }
        return null;
    }

    /// Return authenticated TLS 1.3 cipher-suite metadata for vail-backed
    /// WSS. Cleartext and Zig standard-library TLS transports return null.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.CipherSuite {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedCipherSuite();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedCipherSuite();
        }
        return null;
    }

    /// Return the transcript/HKDF hash implied by the negotiated WSS suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedTranscriptHash();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedTranscriptHash();
        }
        return null;
    }

    /// Start a TLS 1.3 application traffic-key update for vail-backed WSS.
    /// The connection send mutex keeps this control record ordered with every
    /// WebSocket frame writer.
    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.tls_server_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        if (self.tls_vail_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        return error.TlsKeyUpdateUnavailable;
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        if (self.tls_server_conn) |connection| {
            return connection.keyUpdateCounts();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.keyUpdateCounts();
        }
        return null;
    }

    /// Export RFC 8446 channel-bound keying material for vail-backed WSS.
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        if (self.tls_server_conn) |connection| {
            return connection.exportKeyingMaterial(label, context, out);
        }
        if (self.tls_vail_conn) |connection| {
            return connection.exportKeyingMaterial(label, context, out);
        }
        return error.ExporterUnavailable;
    }

    fn bufferInitial(self: *Connection, bytes: []const u8) Error!void {
        try self.inbuf.appendSlice(self.allocator, bytes);
    }

    fn transport(self: *Connection) RuntimeTransport {
        if (self.linux_io_uring) |conn| return .{ .linux_io_uring = conn };
        if (self.tls_server_conn) |conn| return .{ .tls_server = conn };
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn close(self: *Connection) void {
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.message_assembler) |*assembler| assembler.deinit();
        self.inbuf.deinit(self.allocator);
        self.compression_send.deinit(self.allocator);
        self.compression_receive.deinit(self.allocator);
        self.transport().close();
        self.* = undefined;
    }

    pub fn sendText(self: *Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendBinary(self: *Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    /// Send two borrowed slices as one binary message.
    ///
    /// The uncompressed server path submits header, prefix, and payload without
    /// concatenating them; transports with vectored writes use scatter/gather.
    /// The uncompressed client path must mask every payload byte, so each slice
    /// is copied through bounded stack storage while continuing the same
    /// four-byte mask offset. Negotiated compression consumes the same borrowed
    /// slices through Vort's chunked-input API, retaining only compressed wire
    /// output and encoder workspace on the connection.
    pub fn sendBinaryParts(
        self: *Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        if (!canSendOpcode(.binary, self.close_sent, self.close_received)) {
            return error.ConnectionClosed;
        }
        const payload_len = std.math.add(
            usize,
            first.len,
            second.len,
        ) catch return error.PayloadTooLarge;
        if (payload_len > self.limits.max_message_bytes or
            payload_len > self.limits.max_frame_bytes)
        {
            return error.PayloadTooLarge;
        }
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const parts = [_][]const u8{ first, second };
            const compressed = try self.compressMessagePartsLocked(
                &parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                try self.writeFrameLockedExtended(
                    .binary,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                );
                return;
            }
        }

        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        if (self.role == .server) {
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                .binary,
                payload_len,
                .{},
            );
            try self.transport().writeAllSlices(&.{
                header,
                first,
                second,
            });
            return;
        }

        var mask_key: [4]u8 = undefined;
        try std.Io.randomSecure(self.io, &mask_key);
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .binary,
            payload_len,
            .{ .mask_key = mask_key },
        );
        try writeMaskedPayloadParts(
            self.transport(),
            header,
            first,
            second,
            mask_key,
        );
    }

    /// Send one binary message by masking the caller buffer in place.
    ///
    /// This opt-in API matches mutable-buffer WebSocket clients such as
    /// websocket.zig. The payload remains masked after return; callers that
    /// need immutable input should continue using `sendBinary`.
    pub fn sendBinaryInPlace(
        self: *Connection,
        payload: []u8,
    ) Error!void {
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        if (!canSendOpcode(.binary, self.close_sent, self.close_received)) {
            return error.ConnectionClosed;
        }
        try validateOutgoingMessagePayload(.binary, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        var mask_key: [4]u8 = undefined;
        try std.Io.randomSecure(self.io, &mask_key);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            .binary,
            payload,
            .{ .mask_key = mask_key },
        );
        websocket.applyMask(payload, mask_key, 0);
        try self.transport().writeAllParts(header, payload);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPong(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    /// Send Ping once and wait for the matching Pong under one deadline.
    /// Interleaved application frames are returned with ownership so callers
    /// can process them and resume through `continuePingWithDeadline`.
    pub fn pingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingWithDeadline(payload, deadline);
    }

    pub fn pingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.sendPing(payload);
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readPingEvent(payload, deadline);
    }

    /// Resume a Ping after the caller handles an interleaved application
    /// frame, deriving a fresh bounded wait without retransmitting Ping.
    pub fn continuePingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continuePingWithDeadline(
            payload,
            .fromNow(
                self.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn readPingEvent(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(deadline);
            switch (frame.header.opcode) {
                .ping => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .pong => {
                    defer frame.deinit(self.allocator);
                    if (!std.mem.eql(u8, frame.payload, payload)) {
                        return error.UnexpectedPong;
                    }
                    return .{ .pong = {} };
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        try self.sendCloseFrame(.{ .code = code, .reason = reason });
    }

    pub fn sendCloseFrame(self: *Connection, close_frame: ?websocket.CloseFrame) Error!void {
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try self.sendFrame(.close, payload);
    }

    pub fn receiveCloseFrame(self: *Connection) Error!?websocket.OwnedCloseFrame {
        var frame = try self.receiveFrame();
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    pub fn receiveCloseFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!?websocket.OwnedCloseFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveCloseFrameWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive and parse one peer Close frame under an absolute deadline.
    /// Partial frame bytes remain buffered for a later receive. This strict
    /// typed helper rejects an intervening application or control frame.
    pub fn receiveCloseFrameWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?websocket.OwnedCloseFrame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var frame = try self.receiveFrameWithDeadline(deadline);
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    /// Relative-budget counterpart to `receiveFrameWithDeadline`. Partial
    /// frame bytes remain buffered so a later receive can resume exactly.
    pub fn receiveFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one frame under a caller-owned absolute deadline. The same
    /// deadline covers partial headers, payload bytes, and TLS records.
    pub fn receiveFrameWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(deadline);
    }

    /// Send Close once and wait up to `timeout` for peer-close progress.
    ///
    /// Ping/Pong frames are consumed under one absolute deadline. An in-flight
    /// application frame is returned to the caller, who can process it and
    /// call this method again with a new bounded wait; it is never hidden or
    /// discarded.
    pub fn closeWithTimeout(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.closeWithDeadline(close_frame, deadline);
    }

    /// Send Close once and advance the handshake under an absolute deadline.
    /// Reuse this entry point after `.application` to retain one total budget.
    pub fn closeWithDeadline(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (!self.close_sent) try self.sendCloseFrame(close_frame);
        return self.readCloseHandshakeEvent(deadline);
    }

    /// Continue a previously started close handshake under the caller's
    /// original deadline after handling an `.application` event.
    pub fn continueCloseWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (!self.close_sent) return error.InvalidFrame;
        return self.readCloseHandshakeEvent(deadline);
    }

    /// Resume an already-started Close handshake under a new relative wait.
    /// This never emits a second Close frame.
    pub fn continueCloseWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continueCloseWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn readCloseHandshakeEvent(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(deadline);
            switch (frame.header.opcode) {
                .ping, .pong => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendFrame(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (!canSendOpcode(opcode, self.close_sent, self.close_received)) return error.ConnectionClosed;
        try validateOutgoingFramePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        try self.writeFrameLocked(opcode, payload, true);
        if (opcode == .close) self.close_sent = true;
    }

    pub fn sendMessage(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.close_sent, self.close_received)) return error.ConnectionClosed;
        try validateOutgoingMessagePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                try self.writeFrameLockedExtended(
                    opcode,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                );
                return;
            }
        }
        try self.writeFrameLocked(opcode, payload, true);
    }

    pub fn sendFragmented(self: *Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (!canSendOpcode(opcode, self.close_sent, self.close_received)) return error.ConnectionClosed;
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (fragments.len == 0) return error.InvalidFrame;

        if (self.permessage_deflate) {
            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            const plain_len = try fragmentedPayloadLen(fragments);
            if (opcode == .text and !fragmentedTextIsValid(fragments)) {
                return error.InvalidUtf8;
            }
            if (plain_len >= self.compression_threshold) {
                try self.compression_send.prepare(
                    self.allocator,
                    plain_len,
                );
                const compressed = try websocket
                    .compressMessageFragmentsVortIntoWindowWithEncoder(
                    &self.compression_send.encoder.?,
                    &self.compression_send.payload,
                    fragments,
                    self.compression_send_max_window_bits,
                );
                if (compressed.len < plain_len) {
                    try self.writeCompressedFragmentsLocked(
                        opcode,
                        compressed,
                        fragments.len,
                    );
                    return;
                }
            }
            for (fragments, 0..) |fragment, index| {
                const frame_opcode: websocket.Opcode =
                    if (index == 0) opcode else .continuation;
                try self.writeFrameLocked(
                    frame_opcode,
                    fragment,
                    index + 1 == fragments.len,
                );
            }
            return;
        }

        if (opcode == .text) try validateOutgoingFragmentedText(self.allocator, fragments);

        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        for (fragments, 0..) |fragment, index| {
            const frame_opcode: websocket.Opcode =
                if (index == 0) opcode else .continuation;
            try self.writeFrameLocked(
                frame_opcode,
                fragment,
                index + 1 == fragments.len,
            );
        }
    }

    pub fn receiveFrame(self: *Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(null);
    }

    fn receiveFrameInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        errdefer |err| closeAfterReceiveError(self, err);
        if (self.close_sent and self.close_received) return error.ConnectionClosed;
        try self.ensureBufferedWithDeadline(2, deadline);
        const second = self.inbuf.items[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBufferedWithDeadline(header_len, deadline);

        const header = try websocket.FrameHeader.parse(self.inbuf.items);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try ensureIncomingFrameBuffered(self, header, total_len, deadline);

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{ .expect_mask = .unmasked, .allow_rsv1 = self.permessage_deflate },
            .server => .{ .expect_mask = .masked, .allow_rsv1 = self.permessage_deflate },
        };
        var frame = try websocket.parseFrameOptions(self.allocator, self.inbuf.items[0..total_len], parse_options);
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (self.close_received and frame.header.opcode != .close) return error.ConnectionClosed;
        if (frame.header.opcode == .close) self.close_received = true;
        return frame;
    }

    pub fn receiveFrameAuto(self: *Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(null);
    }

    pub fn receiveFrameAutoWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveFrameAutoWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(deadline);
    }

    fn receiveFrameAutoInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        while (true) {
            var frame = try self.receiveFrameInternal(deadline);
            errdefer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    // tungstenite queues automatic Pong replies only while the
                    // connection is still active.  After we have sent Close,
                    // the peer may still deliver in-flight control frames, but
                    // replying with a fresh Pong would write after our close
                    // handshake started.
                    if (!self.close_sent) try self.sendPong(frame.payload);
                    return frame;
                },
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) try self.sendFrame(.close, frame.payload);
                    return frame;
                },
                else => return frame,
            }
        }
    }

    pub fn receiveMessage(self: *Connection) Error!OwnedMessage {
        return self.receiveMessageInternal(null);
    }

    /// Receive one complete message within one relative application budget.
    pub fn receiveMessageWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedMessage {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveMessageInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one complete message under a caller-owned absolute deadline.
    ///
    /// The deadline is deliberately unchanged across continuation and control
    /// frames. Protocols such as MQTT can therefore enforce one packet-level
    /// inactivity budget without WebSocket Ping/Pong traffic extending it.
    pub fn receiveMessageWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.receiveMessageInternal(deadline);
    }

    fn receiveMessageInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        errdefer |err| closeAfterReceiveError(self, err);
        if (self.message_into.active()) return error.InvalidFrame;
        if (self.message_assembler == null) {
            self.message_assembler = websocket.MessageAssembler.initLimited(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }

        while (true) {
            var frame = try self.receiveFrameAutoInternal(deadline);
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping, .pong => continue,
                .close => return error.ConnectionClosed,
                else => {
                    const maybe_message = self.message_assembler.?.feed(frame) catch |err| {
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return @errorCast(err);
                    };
                    if (maybe_message) |message| {
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return finishIncomingMessage(
                            self.allocator,
                            message,
                            self.limits.max_message_bytes,
                        );
                    }
                },
            }
        }
    }

    /// Receive one complete message into caller-owned storage.
    ///
    /// `out` must be at least `limits.max_message_bytes`; this lets the method
    /// consume arbitrarily fragmented messages transactionally without finding
    /// a later fragment that no longer fits after earlier frames were removed
    /// from the transport buffer. Control frames retain the same automatic
    /// Pong/Close behavior as `receiveMessage`. Negotiated compressed messages
    /// use reusable connection scratch and inflate directly into `out`.
    pub fn receiveMessageInto(
        self: *Connection,
        out: []u8,
    ) Error!Message {
        return receiveMessageIntoConnection(self, out, null);
    }

    pub fn receiveMessageIntoWithTimeout(
        self: *Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) Error!Message {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveMessageIntoConnection(
            self,
            out,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Caller-buffer counterpart to `receiveMessageWithDeadline`. The same
    /// absolute deadline spans every fragment, TLS read, and interleaved
    /// control frame while preserving the allocation-avoiding receive path.
    pub fn receiveMessageIntoWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Message {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return receiveMessageIntoConnection(self, out, deadline);
    }

    fn ensureCompressionReceiveScratch(self: *Connection) Error!void {
        try self.compression_receive.prepare(
            self.allocator,
            self.limits.max_message_bytes,
        );
    }

    fn compressMessageLocked(
        self: *Connection,
        payload: []const u8,
    ) Error![]const u8 {
        try self.compression_send.prepare(
            self.allocator,
            payload.len,
        );
        return websocket.compressMessageVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            payload,
            self.compression_send_max_window_bits,
        );
    }

    fn compressMessagePartsLocked(
        self: *Connection,
        parts: []const []const u8,
        payload_len: usize,
    ) Error![]const u8 {
        try self.compression_send.prepare(
            self.allocator,
            payload_len,
        );
        return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            parts,
            self.compression_send_max_window_bits,
        );
    }

    fn writeFrameLocked(self: *Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        try self.writeFrameLockedExtended(opcode, payload, fin, .{});
    }

    fn writeFrameLockedExtended(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
        options: struct { rsv1: bool = false },
    ) Error!void {
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            break :blk key;
        } else null;

        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            opcode,
            payload,
            .{
                .fin = fin,
                .mask_key = mask_key,
                .rsv1 = options.rsv1,
            },
        );
        if (mask_key) |mask| {
            try writeMaskedPayload(
                self.transport(),
                header,
                payload,
                mask,
            );
        } else {
            try self.transport().writeAllParts(header, payload);
        }
    }

    fn writeCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        if (self.role == .client and
            try self.writeMaskedCompressedFragmentsBatchLocked(
                opcode,
                compressed_payload,
                frame_count,
            ))
        {
            return;
        }
        if (self.role == .server) {
            try self.writeUnmaskedCompressedFragmentsLocked(
                opcode,
                compressed_payload,
                frame_count,
            );
            return;
        }
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(compressed_payload.len, frame_count, index);
            try self.writeFrameLockedExtended(
                if (index == 0) opcode else .continuation,
                compressed_payload[range.start..range.end],
                index + 1 == frame_count,
                .{ .rsv1 = index == 0 },
            );
        }
    }

    fn writeMaskedCompressedFragmentsBatchLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!bool {
        const header_bound = std.math.mul(
            usize,
            frame_count,
            websocket.max_frame_header_len,
        ) catch return false;
        const required = std.math.add(
            usize,
            header_bound,
            compressed_payload.len,
        ) catch return false;
        if (required > masked_write_scratch_len) return false;

        // Mask each frame with its own RFC 6455 key, but stage the small
        // compressed message in the same bounded scratch already used by the
        // ordinary client masking path. One transport write then preserves all
        // frame boundaries without sixteen loopback syscalls for a 16-slice
        // application message. Larger messages retain the streaming fallback.
        var encoded: [masked_write_scratch_len]u8 align(64) = undefined;
        var cursor: usize = 0;
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(
                compressed_payload.len,
                frame_count,
                index,
            );
            const payload = compressed_payload[range.start..range.end];
            var mask_key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &mask_key);
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                if (index == 0) opcode else .continuation,
                payload,
                .{
                    .fin = index + 1 == frame_count,
                    .mask_key = mask_key,
                    .rsv1 = index == 0,
                },
            );
            @memcpy(encoded[cursor..][0..header.len], header);
            cursor += header.len;
            try websocket.applyMaskCopy(
                encoded[cursor..][0..payload.len],
                payload,
                mask_key,
                0,
            );
            cursor += payload.len;
        }
        try self.transport().writeAll(encoded[0..cursor]);
        return true;
    }

    fn writeUnmaskedCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        // One logical message can contain many intentionally tiny compressed
        // continuation frames. Batch their stack headers and borrowed payload
        // ranges so TCP/std-TLS perform bounded writes/flushes instead of one
        // per frame. Larger frame counts fall back to the ordinary loop below.
        const max_batched_frames: usize = 16;
        if (frame_count > max_batched_frames) {
            for (0..frame_count) |index| {
                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    index,
                );
                try self.writeFrameLockedExtended(
                    if (index == 0) opcode else .continuation,
                    compressed_payload[range.start..range.end],
                    index + 1 == frame_count,
                    .{ .rsv1 = index == 0 },
                );
            }
            return;
        }

        var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
        var parts: [max_batched_frames * 2][]const u8 = undefined;
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(
                compressed_payload.len,
                frame_count,
                index,
            );
            const payload = compressed_payload[range.start..range.end];
            parts[index * 2] = try websocket.writeFrameHeaderInto(
                &headers[index],
                if (index == 0) opcode else .continuation,
                payload,
                .{
                    .fin = index + 1 == frame_count,
                    .rsv1 = index == 0,
                },
            );
            parts[index * 2 + 1] = payload;
        }
        try self.transport().writeAllSlices(parts[0 .. frame_count * 2]);
    }

    fn ensureBuffered(self: *Connection, len: usize) Error!void {
        return self.ensureBufferedWithDeadline(len, null);
    }

    fn ensureBufferedWithDeadline(
        self: *Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        var scratch: [transport_read_scratch_len]u8 = undefined;
        while (self.inbuf.items.len < len) {
            const n = if (deadline) |absolute|
                try self.transport().readWithDeadline(&scratch, absolute)
            else
                try self.transport().read(&scratch);
            if (n == 0) return error.ConnectionClosed;
            // One socket read commonly returns one complete WebSocket frame.
            // ArrayList's geometric append growth retained roughly 6.5 KiB for
            // every 4 KiB benchmark connection. Exact growth preserves the
            // same reuse while retaining only bytes the transport delivered.
            try appendTransportBytesPrecise(
                &self.inbuf,
                self.allocator,
                scratch[0..n],
            );
        }
    }

    fn discardBuffered(self: *Connection, len: usize) void {
        if (len == self.inbuf.items.len) {
            self.inbuf.clearRetainingCapacity();
            return;
        }
        const remaining = self.inbuf.items[len..];
        @memmove(self.inbuf.items[0..remaining.len], remaining);
        self.inbuf.shrinkRetainingCapacity(remaining.len);
    }
};

pub const H2Connection = struct {
    allocator: std.mem.Allocator,
    tunnel: http2_runtime.Tunnel,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    send_mutex: std.Io.Mutex = .init,
    close_sent: bool = false,
    close_received: bool = false,
    incoming_data_kind: IncomingDataKind = .none,
    incoming_text_utf8: websocket.Utf8Validator = .{},
    incoming_frame_validated: usize = 0,
    message_assembler: ?websocket.MessageAssembler = null,
    message_into: MessageIntoReceiveState = .{},
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,
    compression_threshold: usize = default_compression_threshold,
    compression_send_max_window_bits: u8 = 15,
    compression_send: compression_scratch.SendScratch = .{},
    compression_receive: compression_scratch.Scratch = .{},

    fn init(
        allocator: std.mem.Allocator,
        tunnel: http2_runtime.Tunnel,
        role: Role,
        limits: Limits,
        selected_protocol: ?[]u8,
        negotiated_extension: websocket.ExtensionNegotiation,
        compression_threshold: usize,
    ) H2Connection {
        return .{
            .allocator = allocator,
            .tunnel = tunnel,
            .role = role,
            .limits = limits,
            .selected_protocol = selected_protocol,
            .permessage_deflate = negotiated_extension.permessage_deflate,
            .compression_threshold = compression_threshold,
            .compression_send_max_window_bits = switch (role) {
                .client => negotiated_extension.client_max_window_bits orelse 15,
                .server => negotiated_extension.server_max_window_bits orelse 15,
            },
        };
    }

    pub fn close(self: *H2Connection) void {
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.message_assembler) |*assembler| assembler.deinit();
        self.inbuf.deinit(self.allocator);
        self.compression_send.deinit(self.allocator);
        self.compression_receive.deinit(self.allocator);
        self.* = undefined;
    }

    /// Return TLS identity and negotiation state for the shared HTTP/2
    /// connection. These are connection-wide values, not per-WebSocket-stream
    /// properties, and remain valid while the parent connection is alive.
    pub fn peerCertificates(
        self: *const H2Connection,
    ) ?[]const []const u8 {
        return self.tunnel.connection.peerCertificates();
    }

    pub fn negotiatedAlpn(self: *const H2Connection) ?[]const u8 {
        return self.tunnel.connection.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: *const H2Connection,
    ) ?tls_stream.CipherSuite {
        return self.tunnel.connection.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: *const H2Connection,
    ) ?tls_stream.TranscriptHash {
        return self.tunnel.connection.negotiatedTranscriptHash();
    }

    pub fn exportKeyingMaterial(
        self: *const H2Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.tunnel.connection.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    /// RFC 8441 runs over the parent HTTP/2 connection, so TLS traffic-key
    /// control belongs to that shared transport rather than this logical
    /// WebSocket stream. Cleartext h2c reports the same explicit unavailable
    /// error as the ordinary WebSocket adapter.
    pub fn updateTrafficKeys(
        self: *H2Connection,
        request_peer_update: bool,
    ) Error!void {
        try self.tunnel.connection.updateTrafficKeys(request_peer_update);
    }

    pub fn keyUpdateCounts(
        self: *const H2Connection,
    ) ?tls_stream.KeyUpdateCounts {
        return self.tunnel.connection.keyUpdateCounts();
    }

    pub fn sendText(self: *H2Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendBinary(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    /// RFC 8441 counterpart to `Connection.sendBinaryParts`. The two caller-
    /// owned slices remain one WebSocket message even when HTTP/2 flow control
    /// divides its byte stream into several DATA frames.
    pub fn sendBinaryParts(
        self: *H2Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        if (!canSendOpcode(.binary, self.close_sent, self.close_received)) {
            return error.ConnectionClosed;
        }
        const payload_len = std.math.add(
            usize,
            first.len,
            second.len,
        ) catch return error.PayloadTooLarge;
        if (payload_len > self.limits.max_message_bytes or
            payload_len > self.limits.max_frame_bytes)
        {
            return error.PayloadTooLarge;
        }
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);

        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const parts = [_][]const u8{ first, second };
            const compressed = try self.compressMessagePartsLocked(
                &parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                try self.writeFrameLockedExtended(
                    .binary,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                );
                return;
            }
        }

        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .binary,
            payload_len,
            .{ .mask_key = mask_key },
        );
        const parts = [_][]const u8{ first, second };
        if (mask_key) |mask| {
            try writeMaskedTunnelPayloadSlices(
                &self.tunnel,
                header,
                &parts,
                mask,
            );
        } else {
            try self.tunnel.writeSlices(
                &.{ header, first, second },
                false,
            );
        }
    }

    pub fn sendPing(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPong(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    /// RFC 8441 counterpart to `Connection.pingWithTimeout`.
    pub fn pingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingWithDeadline(payload, deadline);
    }

    pub fn pingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try self.sendPing(payload);
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continuePingWithDeadline(
            payload,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn readPingEvent(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(deadline);
            switch (frame.header.opcode) {
                .ping => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .pong => {
                    defer frame.deinit(self.allocator);
                    if (!std.mem.eql(u8, frame.payload, payload)) {
                        return error.UnexpectedPong;
                    }
                    return .{ .pong = {} };
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendClose(self: *H2Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        try self.sendCloseFrame(.{ .code = code, .reason = reason });
    }

    pub fn sendCloseFrame(self: *H2Connection, close_frame: ?websocket.CloseFrame) Error!void {
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try self.sendFrame(.close, payload);
    }

    pub fn receiveCloseFrame(self: *H2Connection) Error!?websocket.OwnedCloseFrame {
        var frame = try self.receiveFrame();
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    pub fn receiveCloseFrameWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!?websocket.OwnedCloseFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveCloseFrameWithDeadline(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// RFC 8441 counterpart to
    /// `Connection.receiveCloseFrameWithDeadline`.
    pub fn receiveCloseFrameWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?websocket.OwnedCloseFrame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        var frame = try self.receiveFrameWithDeadline(deadline);
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    /// RFC 8441 relative-budget counterpart to
    /// `receiveFrameWithDeadline`.
    pub fn receiveFrameWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// RFC 8441 counterpart to `Connection.receiveFrameWithDeadline`.
    pub fn receiveFrameWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(deadline);
    }

    /// Send Close on the extended CONNECT stream and wait under one absolute
    /// deadline. In-flight application frames are returned rather than lost.
    pub fn closeWithTimeout(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.closeWithDeadline(close_frame, deadline);
    }

    /// RFC 8441 close progress under a caller-owned absolute deadline.
    pub fn closeWithDeadline(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (!self.close_sent) try self.sendCloseFrame(close_frame);
        return self.readCloseHandshakeEvent(deadline);
    }

    /// RFC 8441 close progress under the original caller-owned deadline.
    pub fn continueCloseWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (!self.close_sent) return error.InvalidFrame;
        return self.readCloseHandshakeEvent(deadline);
    }

    pub fn continueCloseWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continueCloseWithDeadline(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn readCloseHandshakeEvent(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(deadline);
            switch (frame.header.opcode) {
                .ping, .pong => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendFrame(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (!canSendOpcode(opcode, self.close_sent, self.close_received)) return error.ConnectionClosed;
        try validateOutgoingFramePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.writeFrameLocked(opcode, payload, true);
        if (opcode == .close) self.close_sent = true;
    }

    pub fn sendMessage(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.close_sent, self.close_received)) return error.ConnectionClosed;
        try validateOutgoingMessagePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);

        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                try self.writeFrameLockedExtended(
                    opcode,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                );
                return;
            }
        }
        try self.writeFrameLocked(opcode, payload, true);
    }

    pub fn sendFragmented(self: *H2Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (!canSendOpcode(opcode, self.close_sent, self.close_received)) return error.ConnectionClosed;
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (fragments.len == 0) return error.InvalidFrame;

        if (self.permessage_deflate) {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            const plain_len = try fragmentedPayloadLen(fragments);
            if (opcode == .text and !fragmentedTextIsValid(fragments)) {
                return error.InvalidUtf8;
            }
            if (plain_len >= self.compression_threshold) {
                try self.compression_send.prepare(
                    self.allocator,
                    plain_len,
                );
                const compressed = try websocket
                    .compressMessageFragmentsVortIntoWindowWithEncoder(
                    &self.compression_send.encoder.?,
                    &self.compression_send.payload,
                    fragments,
                    self.compression_send_max_window_bits,
                );
                if (compressed.len < plain_len) {
                    try self.writeCompressedFragmentsLocked(
                        opcode,
                        compressed,
                        fragments.len,
                    );
                    return;
                }
            }
            return self.writeUncompressedFragmentsLocked(
                opcode,
                fragments,
            );
        }

        if (opcode == .text) try validateOutgoingFragmentedText(self.allocator, fragments);

        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);

        try self.writeUncompressedFragmentsLocked(opcode, fragments);
    }

    pub fn receiveFrame(self: *H2Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(null);
    }

    fn receiveFrameInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        errdefer |err| closeAfterReceiveError(self, err);
        if (self.close_sent and self.close_received) return error.ConnectionClosed;
        try self.ensureBufferedWithDeadline(2, deadline);
        const second = self.inbuf.items[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBufferedWithDeadline(header_len, deadline);

        const header = try websocket.FrameHeader.parse(self.inbuf.items);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try ensureIncomingFrameBuffered(self, header, total_len, deadline);

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{ .expect_mask = .unmasked, .allow_rsv1 = self.permessage_deflate },
            .server => .{ .expect_mask = .masked, .allow_rsv1 = self.permessage_deflate },
        };
        var frame = try websocket.parseFrameOptions(self.allocator, self.inbuf.items[0..total_len], parse_options);
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (self.close_received and frame.header.opcode != .close) return error.ConnectionClosed;
        if (frame.header.opcode == .close) self.close_received = true;
        return frame;
    }

    pub fn receiveFrameAuto(self: *H2Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(null);
    }

    pub fn receiveFrameAutoWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveFrameAutoWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(deadline);
    }

    fn receiveFrameAutoInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        while (true) {
            var frame = try self.receiveFrameInternal(deadline);
            errdefer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    if (!self.close_sent) try self.sendPong(frame.payload);
                    return frame;
                },
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) try self.sendFrame(.close, frame.payload);
                    return frame;
                },
                else => return frame,
            }
        }
    }

    pub fn receiveMessage(self: *H2Connection) Error!OwnedMessage {
        return self.receiveMessageInternal(null);
    }

    pub fn receiveMessageWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedMessage {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveMessageInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one RFC 8441 message under a caller-owned absolute deadline.
    /// HTTP/2 connection-control frames and WebSocket control frames share the
    /// same deadline rather than extending upper-layer inactivity budgets.
    pub fn receiveMessageWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return self.receiveMessageInternal(deadline);
    }

    fn receiveMessageInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        errdefer |err| closeAfterReceiveError(self, err);
        if (self.message_into.active()) return error.InvalidFrame;
        if (self.message_assembler == null) {
            self.message_assembler = websocket.MessageAssembler.initLimited(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }

        while (true) {
            var frame = try self.receiveFrameAutoInternal(deadline);
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping, .pong => continue,
                .close => return error.ConnectionClosed,
                else => {
                    const maybe_message = self.message_assembler.?.feed(frame) catch |err| {
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return @errorCast(err);
                    };
                    if (maybe_message) |message| {
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return finishIncomingMessage(
                            self.allocator,
                            message,
                            self.limits.max_message_bytes,
                        );
                    }
                },
            }
        }
    }

    /// Receive one complete message into caller-owned storage.
    ///
    /// HTTP/2 tunnel chunks may split WebSocket frame headers or payloads. This
    /// adapter decodes uncompressed fragments directly into `out`; compressed
    /// input uses only the reusable codec scratch before inflating into `out`.
    pub fn receiveMessageInto(
        self: *H2Connection,
        out: []u8,
    ) Error!Message {
        return receiveMessageIntoConnection(self, out, null);
    }

    pub fn receiveMessageIntoWithTimeout(
        self: *H2Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) Error!Message {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveMessageIntoConnection(
            self,
            out,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// RFC 8441 caller-buffer receive under one absolute deadline. HTTP/2
    /// connection-control and WebSocket control frames cannot renew it.
    pub fn receiveMessageIntoWithDeadline(
        self: *H2Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Message {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return receiveMessageIntoConnection(self, out, deadline);
    }

    fn ensureCompressionReceiveScratch(self: *H2Connection) Error!void {
        try self.compression_receive.prepare(
            self.allocator,
            self.limits.max_message_bytes,
        );
    }

    fn compressMessageLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error![]const u8 {
        try self.compression_send.prepare(
            self.allocator,
            payload.len,
        );
        return websocket.compressMessageVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            payload,
            self.compression_send_max_window_bits,
        );
    }

    fn compressMessagePartsLocked(
        self: *H2Connection,
        parts: []const []const u8,
        payload_len: usize,
    ) Error![]const u8 {
        try self.compression_send.prepare(
            self.allocator,
            payload_len,
        );
        return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            parts,
            self.compression_send_max_window_bits,
        );
    }

    fn writeFrameLocked(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        try self.writeFrameLockedExtended(opcode, payload, fin, .{});
    }

    fn writeFrameLockedExtended(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
        options: struct { rsv1: bool = false },
    ) Error!void {
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        if (opcode.isControl()) {
            // Control payloads are capped at 125 bytes by RFC 6455, so keep
            // their complete frame on the stack. This also avoids retaining a
            // growable buffer solely for tiny Ping/Pong/Close writes.
            var encoded_storage: [websocket.max_frame_header_len + 125]u8 =
                undefined;
            const frame = try websocket.writeFrameInto(
                &encoded_storage,
                opcode,
                payload,
                .{
                    .fin = fin,
                    .mask_key = mask_key,
                    .rsv1 = options.rsv1,
                },
            );
            try self.tunnel.write(frame, opcode == .close);
            return;
        }
        if (mask_key == null) {
            // RFC 8441 server frames do not require masking. Keep the frame
            // header on the stack and let HTTP/2 frame the header plus borrowed
            // application payload as one ordered tunnel byte sequence.
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                opcode,
                payload,
                .{
                    .fin = fin,
                    .rsv1 = options.rsv1,
                },
            );
            try self.tunnel.writeParts(header, payload, false);
            return;
        }
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            opcode,
            payload,
            .{
                .fin = fin,
                .mask_key = mask_key,
                .rsv1 = options.rsv1,
            },
        );
        const payload_parts = [_][]const u8{payload};
        try writeMaskedTunnelPayloadSlices(
            &self.tunnel,
            header,
            &payload_parts,
            mask_key.?,
        );
    }

    fn writeCompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var writer = try self.tunnel.beginWriteSequence();
        var frame_index: usize = 0;
        while (frame_index < frame_count) {
            const batch_count = @min(
                max_batched_frames,
                frame_count - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;

            if (self.role == .client) {
                // Each RFC 6455 fragment has its own mask key. Batch only when
                // all encoded payload bytes fit bounded stack storage; larger
                // compressed messages stream one frame at a time below.
                var masked: [masked_write_scratch_len]u8 align(64) = undefined;
                var masked_len: usize = 0;
                var fits = true;
                for (0..batch_count) |batch_index| {
                    const index = frame_index + batch_index;
                    const range = compressedFragmentRange(
                        compressed_payload.len,
                        frame_count,
                        index,
                    );
                    if (range.end - range.start >
                        masked.len - masked_len)
                    {
                        fits = false;
                        break;
                    }
                    const payload = compressed_payload[range.start..range.end];
                    var mask_key: [4]u8 = undefined;
                    try std.Io.randomSecure(
                        self.tunnel.connection.io,
                        &mask_key,
                    );
                    parts[batch_index * 2] =
                        try websocket.writeFrameHeaderInto(
                            &headers[batch_index],
                            if (index == 0) opcode else .continuation,
                            payload,
                            .{
                                .fin = index + 1 == frame_count,
                                .mask_key = mask_key,
                                .rsv1 = index == 0,
                            },
                        );
                    try websocket.applyMaskCopy(
                        masked[masked_len..][0..payload.len],
                        payload,
                        mask_key,
                        0,
                    );
                    parts[batch_index * 2 + 1] =
                        masked[masked_len..][0..payload.len];
                    masked_len += payload.len;
                }
                if (fits) {
                    const part_count = std.math.mul(
                        usize,
                        batch_count,
                        2,
                    ) catch return error.PayloadTooLarge;
                    try writer.writeSlices(
                        parts[0..part_count],
                        false,
                    );
                    frame_index += batch_count;
                    continue;
                }

                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    frame_index,
                );
                const payload = compressed_payload[range.start..range.end];
                var mask_key: [4]u8 = undefined;
                try std.Io.randomSecure(
                    self.tunnel.connection.io,
                    &mask_key,
                );
                const header = try websocket.writeFrameHeaderInto(
                    &headers[0],
                    if (frame_index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = frame_index + 1 == frame_count,
                        .mask_key = mask_key,
                        .rsv1 = frame_index == 0,
                    },
                );
                const payload_parts = [_][]const u8{payload};
                try writeMaskedTunnelPayloadSlicesWithWriter(
                    &writer,
                    header,
                    &payload_parts,
                    mask_key,
                );
                frame_index += 1;
                continue;
            }

            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    index,
                );
                const payload = compressed_payload[range.start..range.end];
                parts[batch_index * 2] = try websocket.writeFrameHeaderInto(
                    &headers[batch_index],
                    if (index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = index + 1 == frame_count,
                        .rsv1 = index == 0,
                    },
                );
                parts[batch_index * 2 + 1] = payload;
            }
            const part_count = std.math.mul(
                usize,
                batch_count,
                2,
            ) catch return error.PayloadTooLarge;
            try writer.writeSlices(parts[0..part_count], false);
            frame_index += batch_count;
        }
    }

    fn writeUncompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var writer = try self.tunnel.beginWriteSequence();
        var frame_index: usize = 0;
        while (frame_index < fragments.len) {
            const batch_count = @min(
                max_batched_frames,
                fragments.len - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;

            if (self.role == .client) {
                var masked: [masked_write_scratch_len]u8 align(64) = undefined;
                var masked_len: usize = 0;
                var fits = true;
                for (0..batch_count) |batch_index| {
                    const index = frame_index + batch_index;
                    const payload = fragments[index];
                    if (payload.len > masked.len - masked_len) {
                        fits = false;
                        break;
                    }
                    var mask_key: [4]u8 = undefined;
                    try std.Io.randomSecure(
                        self.tunnel.connection.io,
                        &mask_key,
                    );
                    parts[batch_index * 2] =
                        try websocket.writeFrameHeaderInto(
                            &headers[batch_index],
                            if (index == 0) opcode else .continuation,
                            payload,
                            .{
                                .fin = index + 1 == fragments.len,
                                .mask_key = mask_key,
                            },
                        );
                    try websocket.applyMaskCopy(
                        masked[masked_len..][0..payload.len],
                        payload,
                        mask_key,
                        0,
                    );
                    parts[batch_index * 2 + 1] =
                        masked[masked_len..][0..payload.len];
                    masked_len += payload.len;
                }
                if (fits) {
                    const part_count = std.math.mul(
                        usize,
                        batch_count,
                        2,
                    ) catch return error.PayloadTooLarge;
                    try writer.writeSlices(parts[0..part_count], false);
                    frame_index += batch_count;
                    continue;
                }

                const payload = fragments[frame_index];
                var mask_key: [4]u8 = undefined;
                try std.Io.randomSecure(
                    self.tunnel.connection.io,
                    &mask_key,
                );
                const header = try websocket.writeFrameHeaderInto(
                    &headers[0],
                    if (frame_index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = frame_index + 1 == fragments.len,
                        .mask_key = mask_key,
                    },
                );
                const payload_parts = [_][]const u8{payload};
                try writeMaskedTunnelPayloadSlicesWithWriter(
                    &writer,
                    header,
                    &payload_parts,
                    mask_key,
                );
                frame_index += 1;
                continue;
            }

            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const payload = fragments[index];
                parts[batch_index * 2] = try websocket.writeFrameHeaderInto(
                    &headers[batch_index],
                    if (index == 0) opcode else .continuation,
                    payload,
                    .{ .fin = index + 1 == fragments.len },
                );
                parts[batch_index * 2 + 1] = payload;
            }
            const part_count = std.math.mul(
                usize,
                batch_count,
                2,
            ) catch return error.PayloadTooLarge;
            try writer.writeSlices(parts[0..part_count], false);
            frame_index += batch_count;
        }
    }

    fn ensureBuffered(self: *H2Connection, len: usize) Error!void {
        return self.ensureBufferedWithDeadline(len, null);
    }

    fn ensureBufferedWithDeadline(
        self: *H2Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (self.inbuf.items.len < len) {
            var data = if (deadline) |absolute|
                try self.tunnel.readWithDeadline(absolute)
            else
                try self.tunnel.read();
            defer data.deinit(self.allocator);
            if (data.data.len != 0) try self.inbuf.appendSlice(self.allocator, data.data);
            if (data.end_stream) {
                if (self.inbuf.items.len < len) return error.ConnectionClosed;
                break;
            }
        }
    }

    fn discardBuffered(self: *H2Connection, len: usize) void {
        if (len == self.inbuf.items.len) {
            self.inbuf.clearRetainingCapacity();
            return;
        }
        const remaining = self.inbuf.items[len..];
        @memmove(self.inbuf.items[0..remaining.len], remaining);
        self.inbuf.shrinkRetainingCapacity(remaining.len);
    }
};

pub const H2Client = struct {
    pub fn open(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
    ) Error!H2Connection {
        return openUntil(allocator, connection, options, null);
    }

    /// Complete RFC 8441 negotiation before one absolute awake-clock
    /// deadline. The HTTP/2 connection remains caller-owned on failure.
    pub fn openWithDeadline(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2Connection {
        const absolute = try deadline_policy.usableAwake(
            connection.io,
            deadline,
        );
        return openUntil(allocator, connection, options, absolute);
    }

    pub fn openWithTimeout(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!H2Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return openWithDeadline(
            allocator,
            connection,
            options,
            .fromNow(
                connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn openUntil(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!H2Connection {
        var request_headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer request_headers.deinit(allocator);
        try request_headers.append(allocator, .{ .name = "sec-websocket-version", .value = "13" });
        var protocol_value: std.ArrayList(u8) = .empty;
        defer protocol_value.deinit(allocator);
        if (options.protocols.len != 0) {
            for (options.protocols, 0..) |protocol, index| {
                if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
                if (index != 0) try protocol_value.appendSlice(allocator, ", ");
                try protocol_value.appendSlice(allocator, protocol);
            }
            try request_headers.append(allocator, .{ .name = "sec-websocket-protocol", .value = protocol_value.items });
        }
        if (options.origin) |origin| {
            try request_headers.append(allocator, .{
                .name = "origin",
                .value = origin,
            });
        }
        if (options.enable_permessage_deflate) {
            try request_headers.append(allocator, .{
                .name = "sec-websocket-extensions",
                .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            });
        }
        try validateH2ClientExtraHeaders(options.extra_headers);
        try request_headers.appendSlice(allocator, options.extra_headers);

        const request_options: http2_runtime.RequestOptions = .{
            .method = "CONNECT",
            .path = options.path,
            .scheme = options.scheme,
            .authority = options.authority,
            .protocol = "websocket",
            .headers = request_headers.items,
        };
        var response = if (deadline) |absolute|
            try connection.openExtendedConnectWithDeadline(
                request_options,
                absolute,
            )
        else
            try connection.openExtendedConnect(request_options);
        errdefer response.deinit(allocator);

        const selected_protocol = try validateH2ServerHandshake(allocator, response.headers, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        const selected_extension = try websocket.ExtensionNegotiation.validateResponse(try optionalH2SingletonHeader(response.headers, "sec-websocket-extensions"));
        if (selected_extension.permessage_deflate and !options.enable_permessage_deflate) return error.InvalidExtension;
        const tunnel = response.tunnel;
        response.tunnel = undefined;
        response.deinit(allocator);

        return H2Connection.init(
            allocator,
            tunnel,
            .client,
            options.limits,
            selected_protocol,
            selected_extension,
            options.compression_threshold,
        );
    }
};

pub const H2Server = struct {
    pub fn accept(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
    ) Error!H2Connection {
        return acceptUntil(allocator, connection, options, null);
    }

    pub fn acceptWithDeadline(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2Connection {
        const absolute = try deadline_policy.usableAwake(
            connection.io,
            deadline,
        );
        return acceptUntil(allocator, connection, options, absolute);
    }

    pub fn acceptWithTimeout(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!H2Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return acceptWithDeadline(
            allocator,
            connection,
            options,
            .fromNow(
                connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn acceptUntil(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!H2Connection {
        var request = if (deadline) |absolute|
            try connection.readExtendedConnectRequestWithDeadline(
                "websocket",
                absolute,
            )
        else
            try connection.readExtendedConnectRequest("websocket");
        errdefer request.deinit(allocator);
        const version = try requiredH2SingletonHeader(request.headers, "sec-websocket-version");
        if (!std.mem.eql(u8, version, "13")) return error.InvalidHandshake;
        try rejectH2ExtendedConnectLegacyHeaders(request.headers);
        try origin_policy.validateH2(request.headers, options.allowed_origins);

        const selected_protocol = try selectH2Subprotocol(allocator, request.headers, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        const selected_extension = try acceptH2Extensions(allocator, request.headers, options.enable_permessage_deflate);
        defer if (selected_extension) |extension| allocator.free(extension);
        const negotiated_extension = if (selected_extension) |extension|
            try websocket.ExtensionNegotiation.validateResponse(extension)
        else
            websocket.ExtensionNegotiation{};

        var response_headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer response_headers.deinit(allocator);
        if (selected_protocol) |protocol| try response_headers.append(allocator, .{ .name = "sec-websocket-protocol", .value = protocol });
        if (selected_extension) |extension| try response_headers.append(allocator, .{ .name = "sec-websocket-extensions", .value = extension });
        try validateH2ServerExtraHeaders(options.extra_headers);
        try response_headers.appendSlice(allocator, options.extra_headers);
        if (deadline) |absolute| {
            // Header validation and extension selection remain inside the same
            // admission budget; never send 200 after the deadline has expired.
            _ = try deadline_policy.usableAwake(connection.io, absolute);
        }

        const tunnel = try connection.acceptExtendedConnect(request, response_headers.items);
        request.deinit(allocator);
        return H2Connection.init(
            allocator,
            tunnel,
            .server,
            options.limits,
            selected_protocol,
            negotiated_extension,
            options.compression_threshold,
        );
    }
};

/// Narrow test hook for constructing deliberately split WebSocket frames.
/// Production callers should use the validated public message APIs.
pub const testing = struct {
    pub fn writeFrame(
        connection: anytype,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        return connection.writeFrameLocked(opcode, payload, fin);
    }
};

pub const H2ConnectOptions = struct {
    authority: ?[]const u8 = null,
    path: []const u8 = "/",
    /// Optional RFC 8441 `:scheme`.  When omitted, the HTTP/2 runtime uses the
    /// underlying connection's default (`http` for h2c, `https` for future TLS
    /// h2 connections), matching how mature stacks derive `:scheme` from the
    /// selected transport rather than hard-coding secure origins.
    scheme: ?[]const u8 = null,
    protocols: []const []const u8 = &.{},
    /// Optional browser Origin value sent as a regular RFC 8441 header.
    origin: ?[]const u8 = null,
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    /// RFC 8441 outbound compression threshold; receive negotiation is
    /// independent of this value.
    compression_threshold: usize = default_compression_threshold,
    limits: Limits = .{},
};

pub const H2AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    /// RFC 8441 counterpart to `AcceptOptions.allowed_origins`.
    allowed_origins: []const []const u8 = &.{},
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    /// RFC 8441 outbound compression threshold.
    compression_threshold: usize = default_compression_threshold,
    limits: Limits = .{},
};

fn validateOutgoingMessagePayload(opcode: websocket.Opcode, payload: []const u8) Error!void {
    if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
}

fn validateOutgoingFramePayload(opcode: websocket.Opcode, payload: []const u8) Error!void {
    switch (opcode) {
        // Application data frames must go through sendMessage/sendFragmented so
        // text UTF-8 checks and negotiated permessage-deflate framing cannot be
        // bypassed by the low-level control-frame helper.
        .text, .binary => return error.InvalidFrame,
        .close => try websocket.validateClosePayload(payload),
        .ping, .pong => if (payload.len > 125) return error.InvalidControlFrame,
        .continuation => return error.InvalidFrame,
        _ => return error.InvalidFrame,
    }
}

fn canSendOpcode(opcode: websocket.Opcode, close_sent: bool, close_received: bool) bool {
    if (close_sent) return false;
    if (close_received and opcode != .close) return false;
    return true;
}

/// Assemble a message directly into caller storage for either stream-backed
/// WebSocket transport. Both connection types expose the same buffering and
/// frame-writing contract; keeping the state machine here prevents the HTTP/2
/// adapter from regressing to per-frame ownership and a second whole-message
/// buffer.
fn receiveMessageIntoConnection(
    connection: anytype,
    out: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Message {
    errdefer |err| closeAfterReceiveError(connection, err);
    if (connection.message_assembler != null) return error.InvalidFrame;
    if (out.len < connection.limits.max_message_bytes) {
        return error.BufferTooShort;
    }
    try connection.message_into.validateOutput(out);

    var control_storage: [125]u8 = undefined;
    while (true) {
        const frame_out = if (connection.message_into.compressed)
            connection.compression_receive.payload.items[connection.message_into.written..]
        else
            out[connection.message_into.written..];
        const frame = try receiveFrameIntoConnection(
            connection,
            frame_out,
            &control_storage,
            deadline,
        );
        switch (frame.header.opcode) {
            .ping => {
                if (!connection.close_sent) {
                    try connection.sendPong(frame.payload);
                }
                continue;
            },
            .pong => continue,
            .close => {
                connection.close_received = true;
                if (!connection.close_sent) {
                    try connection.sendFrame(.close, frame.payload);
                }
                return error.ConnectionClosed;
            },
            .text, .binary => {
                if (connection.message_into.active()) {
                    return error.InvalidFrame;
                }
                connection.message_into.begin(
                    out,
                    frame.header.opcode,
                    frame.header.rsv1,
                );
                if (connection.message_into.compressed and
                    !connection.permessage_deflate)
                {
                    return error.UnexpectedRsv;
                }
                if (connection.message_into.compressed) {
                    try connection.ensureCompressionReceiveScratch();
                }
                // The first frame is decoded before its RSV1 bit selects
                // compressed scratch, so copy it exactly once. Continuations
                // then decode directly into retained compressed storage.
                if (connection.message_into.compressed and
                    frame.payload.len != 0)
                {
                    @memcpy(
                        connection.compression_receive
                            .payload.items[0..frame.payload.len],
                        frame.payload,
                    );
                }
            },
            .continuation => {
                if (!connection.message_into.active()) {
                    return error.InvalidFrame;
                }
                if (frame.header.rsv1) return error.UnexpectedRsv;
            },
            else => return error.InvalidFrame,
        }
        connection.message_into.written = std.math.add(
            usize,
            connection.message_into.written,
            frame.payload.len,
        ) catch return error.PayloadTooLarge;
        if (connection.message_into.written >
            connection.limits.max_message_bytes)
        {
            return error.PayloadTooLarge;
        }
        if (!frame.header.fin) continue;

        const message_opcode = connection.message_into.opcode orelse
            return error.InvalidFrame;
        const payload = if (connection.message_into.compressed)
            try websocket.decompressMessageInto(
                out[0..connection.limits.max_message_bytes],
                connection.compression_receive.payload.items[0..connection.message_into.written],
                connection.compression_receive.payload.allocatedSlice(),
                connection.compression_receive.flate_window.?,
            )
        else
            out[0..connection.message_into.written];
        if (message_opcode == .text and
            !std.unicode.utf8ValidateSlice(payload))
        {
            return error.InvalidUtf8;
        }
        connection.message_into.reset();
        return .{ .opcode = message_opcode, .payload = payload };
    }
}

fn receiveFrameIntoConnection(
    connection: anytype,
    out: []u8,
    control_out: *[125]u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!websocket.BorrowedFrame {
    if (connection.close_sent and connection.close_received) {
        return error.ConnectionClosed;
    }
    try connection.ensureBufferedWithDeadline(2, deadline);
    const second = connection.inbuf.items[1];
    var header_len: usize = 2;
    const len_code = second & 0x7f;
    if (len_code == 126) {
        header_len += 2;
    } else if (len_code == 127) {
        header_len += 8;
    }
    if ((second & 0x80) != 0) header_len += 4;
    try connection.ensureBufferedWithDeadline(header_len, deadline);

    const header = try websocket.FrameHeader.parse(connection.inbuf.items);
    const payload_len = std.math.cast(
        usize,
        header.payload_len,
    ) orelse return error.PayloadTooLarge;
    if (payload_len > connection.limits.max_frame_bytes) {
        return error.MessageTooLarge;
    }
    const payload_out = if (header.opcode.isControl())
        control_out[0..]
    else
        out;
    if (payload_len > payload_out.len) return error.PayloadTooLarge;
    const total_len = std.math.add(
        usize,
        header.header_len,
        payload_len,
    ) catch return error.PayloadTooLarge;
    try ensureIncomingFrameBuffered(connection, header, total_len, deadline);
    const parse_options: websocket.ParseFrameOptions = switch (connection.role) {
        .client => .{
            .expect_mask = .unmasked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
        .server => .{
            .expect_mask = .masked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
    };
    const frame = try websocket.parseFrameInto(
        payload_out,
        connection.inbuf.items[0..total_len],
        parse_options,
    );
    connection.discardBuffered(frame.consumed);
    if (connection.close_received and frame.header.opcode != .close) {
        return error.ConnectionClosed;
    }
    return frame;
}

fn closeAfterReceiveError(connection: anytype, err: anyerror) void {
    const code = closeCodeForReceiveError(err) orelse return;
    // Nested receive helpers may observe the same failure. Only the first
    // layer sends a Close frame; later errdefers preserve the original error.
    if (connection.close_sent) return;
    connection.sendClose(code, "") catch {};
}

fn closeCodeForReceiveError(err: anyerror) ?websocket.CloseCode {
    return switch (err) {
        error.InvalidUtf8 => .invalid_payload_data,
        error.MessageTooLarge, error.PayloadTooLarge => .message_too_big,
        error.InvalidOpcode,
        error.InvalidFrame,
        error.InvalidControlFrame,
        error.UnmaskedClientFrame,
        error.MaskedServerFrame,
        error.UnexpectedRsv,
        error.NonMinimalLength,
        error.InvalidCloseCode,
        => .protocol_error,
        else => null,
    };
}

/// Read the current frame body while validating uncompressed text bytes as
/// they arrive from the transport. A complete invalid frame need not be
/// buffered before the peer receives Close 1007; this is the fail-fast behavior
/// recommended by RFC 6455 section 8.1 and exercised by Autobahn 6.4.
fn ensureIncomingFrameBuffered(
    connection: anytype,
    header: websocket.FrameHeader,
    total_len: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    const parse_options: websocket.ParseFrameOptions = switch (connection.role) {
        .client => .{
            .expect_mask = .unmasked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
        .server => .{
            .expect_mask = .masked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
    };
    // Header errors take precedence over payload validation and are known as
    // soon as the complete header is buffered. The full frame parser repeats
    // this check after the payload arrives as a defensive codec boundary.
    try websocket.validateFrameHeader(header, parse_options);
    const message_kind: IncomingDataKind = switch (header.opcode) {
        .text => blk: {
            if (connection.incoming_data_kind != .none) {
                return error.InvalidFrame;
            }
            // A deadline may expire after validating a prefix of this same
            // frame. Preserve the incremental UTF-8 state in that case; reset
            // only when the frame has not been entered before.
            if (connection.incoming_frame_validated == 0) {
                connection.incoming_text_utf8.reset();
            }
            break :blk if (header.rsv1) .compressed_text else .text;
        },
        .binary => blk: {
            if (connection.incoming_data_kind != .none) {
                return error.InvalidFrame;
            }
            break :blk .binary;
        },
        .continuation => blk: {
            if (connection.incoming_data_kind == .none) {
                return error.InvalidFrame;
            }
            break :blk connection.incoming_data_kind;
        },
        else => .none,
    };
    const validate_text = message_kind == .text;
    var validated = @max(
        header.header_len,
        connection.incoming_frame_validated,
    );
    errdefer preserveIncomingFrameValidation(connection, validated);
    while (connection.inbuf.items.len < total_len) {
        if (validate_text) {
            try validateBufferedTextRange(
                connection,
                header,
                &validated,
                total_len,
            );
        }
        try connection.ensureBufferedWithDeadline(
            @min(total_len, connection.inbuf.items.len + 1),
            deadline,
        );
    }
    if (validate_text) {
        try validateBufferedTextRange(
            connection,
            header,
            &validated,
            total_len,
        );
        if (header.fin) try connection.incoming_text_utf8.finish();
    }

    if (!header.opcode.isControl()) {
        connection.incoming_data_kind =
            if (header.fin) .none else message_kind;
    }
    connection.incoming_frame_validated = 0;
}

fn preserveIncomingFrameValidation(
    connection: anytype,
    validated: usize,
) void {
    connection.incoming_frame_validated = validated;
}

fn validateBufferedTextRange(
    connection: anytype,
    header: websocket.FrameHeader,
    validated: *usize,
    total_len: usize,
) Error!void {
    const available_end = @min(connection.inbuf.items.len, total_len);
    if (available_end <= validated.*) return;
    const bytes = connection.inbuf.items[validated.*..available_end];
    if (header.mask_key) |mask| {
        for (bytes, 0..) |byte, index| {
            try connection.incoming_text_utf8.feedByte(
                byte ^ mask[(validated.* - header.header_len + index) & 3],
            );
        }
    } else {
        try connection.incoming_text_utf8.feed(bytes);
    }
    validated.* = available_end;
}

fn finishIncomingMessage(
    allocator: std.mem.Allocator,
    message: websocket.MessageAssembler.Message,
    max_message_bytes: usize,
) Error!OwnedMessage {
    var payload = message.payload;
    if (message.compressed) {
        errdefer allocator.free(message.payload);
        payload = try websocket.decompressMessage(allocator, message.payload, max_message_bytes);
        allocator.free(message.payload);
    }
    errdefer allocator.free(payload);
    if (message.opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
    return .{ .opcode = message.opcode, .payload = payload };
}

fn validateOutgoingFragmentedText(
    allocator: std.mem.Allocator,
    fragments: []const []const u8,
) Error!void {
    _ = allocator;
    if (!fragmentedTextIsValid(fragments)) return error.InvalidUtf8;
}

fn fragmentedPayloadLen(fragments: []const []const u8) Error!usize {
    var total: usize = 0;
    for (fragments) |fragment| {
        total = std.math.add(usize, total, fragment.len) catch
            return error.PayloadTooLarge;
    }
    return total;
}

/// Validate UTF-8 over discontiguous fragments without assembling a copy.
fn fragmentedTextIsValid(fragments: []const []const u8) bool {
    var sequence: [4]u8 = undefined;
    var sequence_len: usize = 0;
    var expected_len: usize = 0;
    for (fragments) |fragment| {
        for (fragment) |byte| {
            if (sequence_len == 0) {
                expected_len = std.unicode.utf8ByteSequenceLength(byte) catch
                    return false;
            }
            sequence[sequence_len] = byte;
            sequence_len += 1;
            if (sequence_len == expected_len) {
                _ = std.unicode.utf8Decode(
                    sequence[0..expected_len],
                ) catch return false;
                sequence_len = 0;
            }
        }
    }
    return sequence_len == 0;
}

const FragmentRange = struct { start: usize, end: usize };

fn compressedFragmentRange(total_len: usize, frame_count: usize, index: usize) FragmentRange {
    std.debug.assert(frame_count != 0);
    std.debug.assert(index < frame_count);
    // permessage-deflate compresses the message as one DEFLATE stream.  RFC 6455
    // fragmentation is then applied to the compressed byte stream, with RSV1 set
    // only on the first frame; boundaries do not have to match caller-provided
    // plaintext fragment boundaries.
    const base = total_len / frame_count;
    const extra = total_len % frame_count;
    const start = index * base + @min(index, extra);
    const len = base + @as(usize, if (index < extra) 1 else 0);
    return .{ .start = start, .end = start + len };
}

const HttpHead = struct {
    head: []u8,
    extra: []u8,

    fn deinit(self: *HttpHead, allocator: std.mem.Allocator) void {
        allocator.free(self.head);
        allocator.free(self.extra);
        self.* = undefined;
    }
};

fn writeHttpUpgradeRequest(allocator: std.mem.Allocator, transport: RuntimeTransport, options: http1_runtime.RequestOptions) Error!void {
    try http1.validateRequestTargetForMethod(options.method, options.target);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var has_host = false;
    for (options.headers) |header| {
        if (header.eqlName("host")) has_host = true;
        try headers.append(allocator, header);
    }
    if (!has_host) {
        if (options.host) |host| try headers.append(allocator, .{ .name = "Host", .value = host });
    }
    try http1.validateHostHeaderBlock(options.version, headers.items);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http1.writeRequestChecked(&encoded, allocator, options.method, options.target, options.version, headers.items, options.body);
    try transport.writeAll(encoded.items);
}

fn readHttpHead(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, max_head_bytes: usize) Error!HttpHead {
    return readHttpHeadFromTransport(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        max_head_bytes,
        null,
    );
}

fn readHttpHeadFromTransport(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    max_head_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!HttpHead {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var scratch: [4096]u8 = undefined;
    while (true) {
        if (try findHttpHeadEndWithinLimit(bytes.items, max_head_bytes)) |head_end| {
            const split = head_end + 4;
            const head = try allocator.dupe(u8, bytes.items[0..split]);
            errdefer allocator.free(head);
            return .{
                .head = head,
                .extra = try allocator.dupe(u8, bytes.items[split..]),
            };
        }
        const read_buf = scratch[0..@min(scratch.len, max_head_bytes - bytes.items.len)];
        const n = if (deadline) |absolute|
            try transport.readWithDeadline(read_buf, absolute)
        else
            try transport.read(read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
    }
}

fn handshakeDeadline(
    transport: RuntimeTransport,
    timeout: std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    const io = switch (transport) {
        .tcp => |tcp| tcp.io,
        .tls => |connection| connection.io,
        .tls_vail => |connection| connection.io,
        .tls_server => |connection| connection.io,
        .linux_io_uring => return error.TimedReadUnsupported,
    };
    return .fromNow(io, .{ .raw = timeout, .clock = .awake });
}

fn findHttpHeadEndWithinLimit(bytes: []const u8, max_head_bytes: usize) Error!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

fn validateServerHandshake(
    allocator: std.mem.Allocator,
    response: http1.Response,
    client_key: []const u8,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
    if (response.version != .http_1_1) return error.InvalidHandshake;
    const upgrade = try requiredSingletonHeader(response.headers, "upgrade");
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.InvalidHandshake;
    if (!hasHeader(response.headers, "connection")) return error.MissingHeader;
    if (!headersContainToken(response.headers, "connection", "upgrade")) return error.InvalidHandshake;
    if ((try http1.contentLength(response.headers)) != null) return error.InvalidHandshake;
    for (response.headers) |header| {
        if (header.eqlName("transfer-encoding")) return error.InvalidHandshake;
    }
    const accept = try requiredSingletonHeader(response.headers, "sec-websocket-accept");
    const expected = websocket.acceptKey(client_key);
    if (!std.mem.eql(u8, accept, &expected)) return error.InvalidHandshake;
    _ = try websocket.ExtensionNegotiation.validateResponse(try optionalSingletonHeader(response.headers, "sec-websocket-extensions"));
    if (try optionalSingletonHeader(response.headers, "sec-websocket-protocol")) |selected| {
        const protocol = wire.trimOws(selected);
        if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) return try allocator.dupe(u8, protocol);
        }
        return error.InvalidSubprotocol;
    }
    if (offered_protocols.len != 0) return error.InvalidSubprotocol;
    return null;
}

fn requiredSingletonHeader(headers: []const http1.Header, name: []const u8) Error![]const u8 {
    return (try optionalSingletonHeader(headers, name)) orelse error.MissingHeader;
}

fn optionalSingletonHeader(headers: []const http1.Header, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn headersContainToken(headers: []const http1.Header, name: []const u8, token: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name) and wire.containsToken(header.value, token)) return true;
    }
    return false;
}

fn validateH2ServerHandshake(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
    try rejectH2ExtendedConnectLegacyHeaders(headers);
    if (try optionalH2SingletonHeader(headers, "sec-websocket-version")) |_| return error.InvalidHandshake;
    if (try optionalH2SingletonHeader(headers, "sec-websocket-protocol")) |selected| {
        const protocol = wire.trimOws(selected);
        if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) return try allocator.dupe(u8, protocol);
        }
        return error.InvalidSubprotocol;
    }
    if (offered_protocols.len != 0) return error.InvalidSubprotocol;
    return null;
}

fn requiredH2SingletonHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) Error![]const u8 {
    return (try optionalH2SingletonHeader(headers, name)) orelse error.MissingHeader;
}

fn optionalH2SingletonHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

fn validateH2ClientExtraHeaders(headers: []const http2.Hpack.HeaderField) Error!void {
    for (headers) |header| {
        // RFC 8441 replaces the HTTP/1 key/accept challenge with HTTP/2
        // extended CONNECT.  Keep runtime-owned fields out of caller-provided
        // extras so a request cannot carry duplicate or legacy handshake state.
        if (h2ClientOwnedWebSocketHeader(header.name) or h2LegacyHandshakeHeader(header.name)) return error.InvalidHandshake;
    }
}

fn validateH2ServerExtraHeaders(headers: []const http2.Hpack.HeaderField) Error!void {
    for (headers) |header| {
        // The server helper derives protocol/extension response fields from the
        // validated request and local options.  Reject caller-supplied copies for
        // the same reason tungstenite rejects duplicate critical HTTP/1 headers.
        if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-protocol") or
            std.ascii.eqlIgnoreCase(header.name, "sec-websocket-extensions") or
            std.ascii.eqlIgnoreCase(header.name, "sec-websocket-version") or
            h2LegacyHandshakeHeader(header.name)) return error.InvalidHandshake;
    }
}

fn rejectH2ExtendedConnectLegacyHeaders(headers: []const http2.Hpack.HeaderField) Error!void {
    for (headers) |header| {
        if (h2LegacyHandshakeHeader(header.name)) return error.InvalidHandshake;
    }
}

fn h2ClientOwnedWebSocketHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "sec-websocket-version") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-extensions");
}

fn h2LegacyHandshakeHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "sec-websocket-key") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-accept");
}

fn acceptH2Extensions(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    enable_permessage_deflate: bool,
) Error!?[]u8 {
    if (!enable_permessage_deflate) return null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "sec-websocket-extensions")) continue;
        if (try websocket.ExtensionNegotiation.accept(allocator, header.value, true)) |accepted| return accepted;
    }
    return null;
}

fn findH2Header(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn selectSubprotocol(allocator: std.mem.Allocator, requested_header: ?[]const u8, supported: []const []const u8) Error!?[]u8 {
    try validateSupportedSubprotocols(supported);
    const raw_requested = requested_header orelse return null;
    var selected: ?[]const u8 = null;
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(allocator);
    try considerSubprotocolHeader(allocator, raw_requested, supported, &selected, &seen);
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn selectHttp1Subprotocol(allocator: std.mem.Allocator, headers: []const http1.Header, supported: []const []const u8) Error!?[]u8 {
    try validateSupportedSubprotocols(supported);
    var selected: ?[]const u8 = null;
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(allocator);
    for (headers) |header| {
        if (!header.eqlName("sec-websocket-protocol")) continue;
        // Sec-WebSocket-Protocol has 1#token grammar.  HTTP/1 field lines may
        // arrive split rather than coalesced, so validate all occurrences and
        // choose the first client-preferred protocol we support instead of
        // silently ignoring later field lines.
        try considerSubprotocolHeader(allocator, header.value, supported, &selected, &seen);
    }
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn selectH2Subprotocol(allocator: std.mem.Allocator, headers: []const http2.Hpack.HeaderField, supported: []const []const u8) Error!?[]u8 {
    try validateSupportedSubprotocols(supported);
    var selected: ?[]const u8 = null;
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(allocator);
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "sec-websocket-protocol")) continue;
        try considerSubprotocolHeader(allocator, header.value, supported, &selected, &seen);
    }
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn validateSupportedSubprotocols(supported: []const []const u8) Error!void {
    for (supported) |protocol| {
        if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
    }
}

fn considerSubprotocolHeader(
    allocator: std.mem.Allocator,
    raw_requested: []const u8,
    supported: []const []const u8,
    selected: *?[]const u8,
    seen: *std.ArrayList([]const u8),
) Error!void {
    var requested = std.mem.splitScalar(u8, raw_requested, ',');
    while (requested.next()) |raw| {
        const candidate = wire.trimOws(raw);
        if (!websocket.validSubprotocolToken(candidate)) return error.InvalidSubprotocol;
        for (seen.items) |previous| {
            // The HTTP/1 upgrade validator already rejects duplicate requested
            // subprotocol names.  Apply the same invariant to all selector
            // helpers, including RFC 8441 extended CONNECT, so a peer cannot
            // bias preference handling by repeating the same token in split
            // header fields.
            if (std.mem.eql(u8, previous, candidate)) return error.InvalidSubprotocol;
        }
        try seen.append(allocator, candidate);
        if (selected.* != null) continue;
        for (supported) |protocol| {
            if (std.mem.eql(u8, candidate, protocol)) {
                selected.* = protocol;
                break;
            }
        }
    }
}

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
}

fn readSomeWithDeadline(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) Error!usize {
    return stream_io.readSomeWithDeadline(io, stream, buffer, deadline);
}

fn setLinuxTcpNoDelay(fd: std.os.linux.fd_t) Error!void {
    if (comptime builtin.os.tag != .linux) return;
    const enabled: c_int = 1;
    const bytes = std.mem.asBytes(&enabled);
    const result = std.os.linux.setsockopt(
        fd,
        std.os.linux.IPPROTO.TCP,
        std.os.linux.TCP.NODELAY,
        bytes.ptr,
        @intCast(bytes.len),
    );
    return switch (std.os.linux.errno(result)) {
        .SUCCESS => {},
        .NOMEM, .NOBUFS => error.SystemResources,
        .NOPROTOOPT => error.ProtocolUnsupportedBySystem,
        else => error.IoUringOperationFailed,
    };
}

fn writeAllToStream(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

fn writeMaskedPayload(
    transport: RuntimeTransport,
    header: []const u8,
    payload: []const u8,
    mask_key: [4]u8,
) Error!void {
    if (payload.len == 0) {
        try transport.writeAll(header);
        return;
    }

    var scratch: [masked_write_scratch_len]u8 = undefined;
    var offset: usize = 0;
    while (offset < payload.len) {
        const count = @min(scratch.len, payload.len - offset);
        try websocket.applyMaskCopy(
            scratch[0..count],
            payload[offset..][0..count],
            mask_key,
            offset,
        );
        if (offset == 0) {
            try transport.writeAllParts(header, scratch[0..count]);
        } else {
            try transport.writeAll(scratch[0..count]);
        }
        offset += count;
    }
}

fn writeMaskedPayloadParts(
    transport: RuntimeTransport,
    header: []const u8,
    first: []const u8,
    second: []const u8,
    mask_key: [4]u8,
) Error!void {
    var scratch: [masked_write_scratch_len]u8 = undefined;
    const parts = [_][]const u8{ first, second };
    var part_index: usize = 0;
    var part_offset: usize = 0;
    var mask_offset: usize = 0;
    var header_pending = true;

    while (part_index < parts.len) {
        var count: usize = 0;
        while (part_index < parts.len and count < scratch.len) {
            const part = parts[part_index];
            if (part_offset == part.len) {
                part_index += 1;
                part_offset = 0;
                continue;
            }
            const chunk_len = @min(
                scratch.len - count,
                part.len - part_offset,
            );
            try websocket.applyMaskCopy(
                scratch[count..][0..chunk_len],
                part[part_offset..][0..chunk_len],
                mask_key,
                mask_offset,
            );
            count += chunk_len;
            part_offset += chunk_len;
            mask_offset += chunk_len;
        }
        if (count == 0) break;
        if (header_pending) {
            try transport.writeAllParts(header, scratch[0..count]);
            header_pending = false;
        } else {
            try transport.writeAll(scratch[0..count]);
        }
    }
    if (header_pending) try transport.writeAll(header);
}

fn writeMaskedTunnelPayloadSlices(
    tunnel: *http2_runtime.Tunnel,
    header: []const u8,
    payload_parts: []const []const u8,
    mask_key: [4]u8,
) Error!void {
    var writer = try tunnel.beginWriteSequence();
    return writeMaskedTunnelPayloadSlicesWithWriter(
        &writer,
        header,
        payload_parts,
        mask_key,
    );
}

fn writeMaskedTunnelPayloadSlicesWithWriter(
    writer: *http2_runtime.TunnelWriter,
    header: []const u8,
    payload_parts: []const []const u8,
    mask_key: [4]u8,
) Error!void {
    var scratch: [masked_write_scratch_len]u8 = undefined;
    var part_index: usize = 0;
    var part_offset: usize = 0;
    var mask_offset: usize = 0;
    var header_pending = true;
    while (part_index < payload_parts.len) {
        var count: usize = 0;
        while (part_index < payload_parts.len and count < scratch.len) {
            const part = payload_parts[part_index];
            if (part_offset == part.len) {
                part_index += 1;
                part_offset = 0;
                continue;
            }
            const chunk_len = @min(
                scratch.len - count,
                part.len - part_offset,
            );
            try websocket.applyMaskCopy(
                scratch[count..][0..chunk_len],
                part[part_offset..][0..chunk_len],
                mask_key,
                mask_offset,
            );
            count += chunk_len;
            part_offset += chunk_len;
            mask_offset += chunk_len;
        }
        if (count == 0) break;
        if (header_pending) {
            try writer.writeParts(header, scratch[0..count], false);
            header_pending = false;
        } else {
            try writer.write(scratch[0..count], false);
        }
    }
    if (header_pending) try writer.write(header, false);
}

test "WebSocket client handshake accepts split Connection and rejects duplicate critical headers" {
    const allocator = std.testing.allocator;
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";

    const split_connection =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var response = try http1.parseResponse(allocator, split_connection, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(?[]u8, null), try validateServerHandshake(allocator, response, client_key, &.{}));
    try std.testing.expectError(error.InvalidSubprotocol, validateServerHandshake(allocator, response, client_key, &.{"chat.v1"}));

    const duplicate_accept =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var duplicate_response = try http1.parseResponse(allocator, duplicate_accept, .{});
    defer duplicate_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, duplicate_response, client_key, &.{}));

    const duplicate_extensions =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "\r\n";
    var duplicate_extensions_response = try http1.parseResponse(allocator, duplicate_extensions, .{});
    defer duplicate_extensions_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, duplicate_extensions_response, client_key, &.{}));

    const content_length_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    var content_length_response = try http1.parseResponse(allocator, content_length_101, .{});
    defer content_length_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, content_length_response, client_key, &.{}));

    const transfer_encoding_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    var transfer_encoding_response = try http1.parseResponse(allocator, transfer_encoding_101, .{});
    defer transfer_encoding_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, transfer_encoding_response, client_key, &.{}));
}

test "WebSocket server negotiates split subprotocol request headers" {
    const allocator = std.testing.allocator;

    const selected = (try selectHttp1Subprotocol(
        allocator,
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "unknown" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2, chat.v1" },
        },
        &.{ "chat.v1", "chat.v2" },
    )).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("chat.v2", selected);

    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1, bad protocol" }},
        &.{"chat.v1"},
    ));
    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" }},
        &.{"bad supported"},
    ));
    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2, chat.v1" },
        },
        &.{ "chat.v1", "chat.v2" },
    ));
}

test "WebSocket over HTTP/2 handshake rejects duplicate critical headers" {
    const allocator = std.testing.allocator;

    const duplicate_request_version = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-version", .value = "13" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try std.testing.expectError(error.InvalidHandshake, requiredH2SingletonHeader(&duplicate_request_version, "sec-websocket-version"));

    try std.testing.expectError(error.InvalidHandshake, validateH2ClientExtraHeaders(&.{
        .{ .name = "sec-websocket-version", .value = "13" },
    }));
    try std.testing.expectError(error.InvalidHandshake, validateH2ClientExtraHeaders(&.{
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    }));

    const duplicate_response_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(std.testing.allocator, &duplicate_response_protocol, &.{"chat.v1"}));
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerExtraHeaders(&.{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    }));

    const legacy_accept_response = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-accept", .value = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(allocator, &legacy_accept_response, &.{}));

    const legacy_key_request = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    };
    try std.testing.expectError(error.InvalidHandshake, rejectH2ExtendedConnectLegacyHeaders(&legacy_key_request));

    const duplicate_extensions = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
    };
    try std.testing.expectError(error.InvalidHandshake, optionalH2SingletonHeader(&duplicate_extensions, "sec-websocket-extensions"));

    const split_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "x-unknown" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted = try acceptH2Extensions(allocator, &split_offer, true);
    defer if (accepted) |value| allocator.free(value);
    try std.testing.expect(accepted != null);

    const split_protocol_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "unknown" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v2, chat.v1" },
    };
    const selected = (try selectH2Subprotocol(allocator, &split_protocol_offer, &.{ "chat.v1", "chat.v2" })).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("chat.v2", selected);

    const invalid_split_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "bad protocol" },
    };
    try std.testing.expectError(error.InvalidSubprotocol, selectH2Subprotocol(allocator, &invalid_split_protocol, &.{"chat.v1"}));
    const duplicate_split_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v2, chat.v1" },
    };
    try std.testing.expectError(error.InvalidSubprotocol, selectH2Subprotocol(allocator, &duplicate_split_protocol, &.{ "chat.v1", "chat.v2" }));
    try std.testing.expectError(error.InvalidSubprotocol, validateH2ServerHandshake(allocator, &.{}, &.{"chat.v1"}));
}

test "WebSocket runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expect(frame.header.masked);
            try std.testing.expectEqualStrings("hello", frame.payload);

            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            try std.testing.expect(connection.close_received);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/chat",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
    try std.testing.expect(!response.header.masked);
    try std.testing.expectEqualStrings("world", response.payload);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime streams large immutable payload without mutation" {
    const allocator = std.testing.allocator;
    const payload_len = masked_write_scratch_len + 257;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    );
    defer server.deinit();

    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);
    const expected = try allocator.dupe(u8, payload);
    defer allocator.free(expected);

    const Shared = struct {
        server: *Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept(.{});
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                message.payload,
            );
            try connection.sendBinary(message.payload);
            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server, .expected = expected };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/immutable-large",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    });
    defer client.close();
    try client.sendBinary(payload);
    try std.testing.expectEqualSlices(u8, expected, payload);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, expected, response.payload);
    try client.sendClose(.normal_closure, "");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket binary parts preserve one frame and continuous masking" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
            try std.testing.expect(frame.header.fin);
            try std.testing.expectEqualStrings("prefix-payload", frame.payload);
            try connection.sendBinaryParts("reply-", "parts");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/binary-parts",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try client.sendBinaryParts("prefix-", "payload");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, response.header.opcode);
    try std.testing.expectEqualStrings("reply-parts", response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{ .protocols = &.{ "chat.v2", "superchat" } });
            defer connection.close();
            try std.testing.expectEqualStrings("superchat", connection.selected_protocol.?);

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", frame.payload);
            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/subprotocol",
        .protocols = &.{ "video", "superchat" },
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectEqualStrings("superchat", client.selected_protocol.?);

    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by host name" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", request.payload);
            try connection.sendText("dns-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .target = "/dns",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("dns-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by ws URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("uri-hello", request.payload);
            try connection.sendText("uri-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://localhost:{d}/uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var client = try Client.connectUri(allocator, io, uri, .{
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("uri-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("uri-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(error.UnsupportedScheme, Client.connectUri(allocator, io, "ftp://localhost/chat", .{}));
    try std.testing.expectError(error.InvalidUri, Client.connectUri(allocator, io, "ws:///missing-host", .{}));
    try std.testing.expectError(error.InvalidUri, Client.connectUri(allocator, io, "ws://user:pass@localhost/chat", .{}));
}

test "WebSocket client connects over Linux io_uring" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var ring = std.os.linux.IoUring.init(16, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => return error.SkipZigTest,
        else => |e| return e,
    };
    defer ring.deinit();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{
                .protocols = &.{"chat.v1"},
                .enable_permessage_deflate = true,
            });
            defer connection.close();
            try std.testing.expectEqualStrings("chat.v1", connection.selected_protocol.?);
            try std.testing.expect(connection.permessage_deflate);

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("uring-websocket-hello", request.payload);
            try connection.sendFragmented(.text, &.{ "uring ", "websocket ", "world" });

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://127.0.0.1:{d}/uring-ws", .{server.address().ip4.port});
    defer allocator.free(uri);
    var client = try Client.connectUriLinuxIoUring(allocator, io, &ring, uri, .{
        .protocols = &.{"chat.v1"},
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectEqualStrings("chat.v1", client.selected_protocol.?);
    try std.testing.expect(client.permessage_deflate);

    try client.sendText("uring-websocket-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("uring websocket world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("ipv6-uri-hello", request.payload);
            try connection.sendText("ipv6-uri-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://[::1]:{d}/ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var client = try Client.connectUri(allocator, io, uri, .{
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("ipv6-uri-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ipv6-uri-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates permessage-deflate" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{ .enable_permessage_deflate = true });
            defer connection.close();
            try std.testing.expect(connection.permessage_deflate);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(server_ptr.http.allocator);
            for (0..3) |index| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try compressed.appendSlice(
                    server_ptr.http.allocator,
                    frame.payload,
                );
            }
            const request = try websocket.decompressMessage(
                server_ptr.http.allocator,
                compressed.items,
                4096,
            );
            defer server_ptr.http.allocator.free(request);
            try std.testing.expectEqualStrings(
                "compressible \xe2\x82\xac compressible compressible",
                request,
            );

            try connection.sendFragmented(.text, &.{ "deflated response ", "deflated response" });

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/deflate",
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expect(client.permessage_deflate);

    // Split one UTF-8 scalar across the application slices. Compression must
    // still produce one DEFLATE message, then preserve the requested three
    // WebSocket frames with RSV1 set only on the first frame.
    try client.sendFragmented(.text, &.{
        "compressible \xe2",
        "\x82",
        "\xac compressible compressible",
    });
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings("deflated response deflated response", response.payload);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 extended CONNECT exchanges messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();

            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .protocols = &.{"chat.v1"},
                .enable_permessage_deflate = true,
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
            });
            defer ws.close();
            try std.testing.expectEqualStrings("chat.v1", ws.selected_protocol.?);
            try std.testing.expect(ws.permessage_deflate);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(server_ptr.allocator);
            for (0..3) |index| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try compressed.appendSlice(
                    server_ptr.allocator,
                    frame.payload,
                );
            }
            const request = try websocket.decompressMessage(
                server_ptr.allocator,
                compressed.items,
                4096,
            );
            defer server_ptr.allocator.free(request);
            try std.testing.expectEqualStrings(
                "hello \xe2\x82\xac over h2 websocket hello over h2 websocket",
                request,
            );

            try ws.sendFragmented(.text, &.{
                "world over h2 websocket ",
                "world over h2 websocket",
            });

            // The h2 WebSocket adapter still runs the normal RFC 6455 close
            // handshake inside DATA frames and maps the final Close write to
            // END_STREAM on the underlying HTTP/2 tunnel.
            try std.testing.expectError(error.ConnectionClosed, ws.receiveMessage());
            try std.testing.expect(ws.close_received);
            try std.testing.expect(ws.close_sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();

    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/chat",
        .protocols = &.{"chat.v1"},
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer ws_client.close();
    try std.testing.expectEqualStrings("chat.v1", ws_client.selected_protocol.?);
    try std.testing.expect(ws_client.permessage_deflate);

    try ws_client.sendFragmented(.text, &.{
        "hello \xe2",
        "\x82",
        "\xac over h2 websocket hello over h2 websocket",
    });
    var response_storage: [4096]u8 = undefined;
    const response = try ws_client.receiveMessageIntoWithDeadline(
        &response_storage,
        .fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings(
        "world over h2 websocket world over h2 websocket",
        response.payload,
    );

    try ws_client.sendClose(.normal_closure, "bye");
    try std.testing.expectError(error.ConnectionClosed, ws_client.receiveMessage());
    try std.testing.expect(ws_client.close_received);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 handshake timeout bounds CONNECT response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var request = try h2.readExtendedConnectRequestWithTimeout(
                "websocket",
                .fromSeconds(1),
            );
            defer request.deinit(self.server.allocator);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    try std.testing.expectError(
        error.Timeout,
        H2Client.openWithTimeout(
            allocator,
            &h2_client,
            .{
                .authority = "localhost",
                .path = "/slow-response",
            },
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(!h2_client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 server handshake resumes after idle timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        io: std.Io,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            try std.testing.expectError(
                error.Timeout,
                H2Server.acceptWithTimeout(
                    self.server.allocator,
                    &h2,
                    .{},
                    .fromMilliseconds(30),
                ),
            );
            self.timed_out.set(self.io);

            var ws = try H2Server.acceptWithTimeout(
                self.server.allocator,
                &h2,
                .{},
                .fromSeconds(1),
            );
            defer ws.close();
            try ws.sendText("accepted-after-timeout");
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    try shared.timed_out.wait(io);
    if (shared.err) |err| return err;
    var ws_client = try H2Client.openWithTimeout(
        allocator,
        &h2_client,
        .{ .authority = "localhost", .path = "/after-timeout" },
        .fromSeconds(1),
    );
    defer ws_client.close();
    var message = try ws_client.receiveMessageWithTimeout(.fromSeconds(1));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings(
        "accepted-after-timeout",
        message.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 timeout APIs reject non-positive budgets" {
    var connection: http2_runtime.Connection = undefined;
    try std.testing.expectError(
        error.Timeout,
        H2Client.openWithTimeout(
            std.testing.allocator,
            &connection,
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        H2Server.acceptWithTimeout(
            std.testing.allocator,
            &connection,
            .{},
            .zero,
        ),
    );
}

test "WebSocket client rejects unoffered subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(server_ptr.http.allocator, head.head, .{});
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try websocket.writeServerHandshake(&response, server_ptr.http.allocator, key, &.{.{ .name = "Sec-WebSocket-Protocol", .value = "not-offered" }});
            try writeAllToStream(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidSubprotocol, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/bad-subprotocol",
        .protocols = &.{"superchat"},
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client rejects HTTP/1.0 upgrade responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(server_ptr.http.allocator, head.head, .{});
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            const accept = websocket.acceptKey(key);
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try response.appendSlice(server_ptr.http.allocator, "HTTP/1.0 101 Switching Protocols\r\n");
            try response.appendSlice(server_ptr.http.allocator, "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
            try response.appendSlice(server_ptr.http.allocator, &accept);
            try response.appendSlice(server_ptr.http.allocator, "\r\n\r\n");
            try writeAllToStream(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidHandshake, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/http10-response",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket server rejects data sent with HTTP upgrade request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                if (err == error.InvalidHandshake) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            connection.close();
            shared.err = error.InvalidHandshake;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try request.appendSlice(
        allocator,
        "GET /early HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    try websocket.writeFrame(&request, allocator, .text, "too early", .{ .mask_key = .{ 1, 2, 3, 4 } });
    try writeAllToStream(io, stream, request.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "WebSocket over HTTP/2 receiveFrameAuto replies to ping" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
    defer backend.deinit();
    const io = backend.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer ws.close();
            var ping = try ws.receiveFrameAuto();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("h2-auto?", ping.payload);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-auto-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer ws_client.close();

    try ws_client.sendPing("h2-auto?");
    var pong = try ws_client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("h2-auto?", pong.payload);
    try ws_client.sendClose(.normal_closure, "bye");
    var close = try ws_client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 control sends do not retain frame scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer ws.close();
            var ping = try ws.receiveFrame();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try ws.sendPong(ping.payload);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/control-stack",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("stack");
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("stack", pong.payload);
    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 application frames avoid retained send scratch" {
    const allocator = std.testing.allocator;
    const payload = "borrowed-rfc8441-payload-" ** 700;
    const h2_limits: http2_runtime.Limits = .{
        // An 8-KiB stream window makes each sender wait for several peer
        // WINDOW_UPDATE frames. It also places the WebSocket header/payload
        // join inside the first DATA frame, while a message larger than the
        // 16-KiB masking buffer verifies continuity across stack chunks.
        .initial_window_size = 8 * 1024,
        .max_body_bytes = payload.len + websocket.max_frame_header_len,
        .enable_connect_protocol = true,
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h2_limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = payload.len,
                    .max_message_bytes = payload.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.opcode);
            try std.testing.expectEqualStrings(payload, request.payload);
            try ws.sendBinaryParts(
                payload[0..19],
                payload[19..],
            );
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        h2_limits,
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/borrowed-frame",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();

    try client.sendBinaryParts(
        payload[0..41],
        payload[41..],
    );
    var message = try client.receiveMessage();
    defer message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
    try std.testing.expectEqualStrings(payload, message.payload);
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 compressed binary parts preserve one message" {
    const allocator = std.testing.allocator;
    const first = "h2-compressed-prefix-";
    const second = "compressible-borrowed-payload-" ** 64;
    const expected = first ++ second;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = expected.len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = expected.len,
                    .max_message_bytes = expected.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.opcode);
            try std.testing.expectEqualStrings(expected, request.payload);
            try ws.sendBinaryParts(first, second);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = expected.len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compressed-binary-parts",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = expected.len,
            .max_message_bytes = expected.len,
        },
    });
    defer client.close();

    try client.sendBinaryParts(first, second);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
    try std.testing.expectEqualStrings(expected, response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 compressed fragments reuse bounded send storage" {
    const allocator = std.testing.allocator;
    const payload_len = 64 * 1024;
    var payload: [payload_len]u8 = undefined;
    var random_state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (payload[0 .. payload.len / 2]) |*byte| {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 7;
        random_state ^= random_state << 17;
        byte.* = @truncate(random_state);
    }
    @memcpy(payload[payload.len / 2 ..], payload[0 .. payload.len / 2]);
    const fragments = [_][]const u8{
        payload[0..7000],
        payload[7000..28_000],
        payload[28_000..],
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = payload_len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = payload_len,
                    .max_message_bytes = payload_len,
                },
            });
            defer ws.close();

            for (0..2) |iteration| {
                var request = try ws.receiveMessage();
                defer request.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    websocket.Opcode.binary,
                    request.opcode,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    shared.expected,
                    request.payload,
                );
                const response_fragments = [_][]const u8{
                    request.payload[0..7000],
                    request.payload[7000..28_000],
                    request.payload[28_000..],
                };
                if (iteration == 0) {
                    try ws.sendFragmented(.binary, &response_fragments);
                    try std.testing.expect(
                        ws.compression_send.payload.items.len >
                            masked_write_scratch_len,
                    );
                } else {
                    var failing = std.testing.FailingAllocator.init(
                        server_ptr.allocator,
                        .{},
                    );
                    ws.allocator = failing.allocator();
                    defer ws.allocator = server_ptr.allocator;
                    failing.fail_index = failing.alloc_index;
                    try ws.sendFragmented(.binary, &response_fragments);
                    try std.testing.expect(!failing.has_induced_failure);
                }
            }
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = payload_len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compressed-fragments-no-send-buffer",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    });
    defer client.close();

    for (0..2) |iteration| {
        if (iteration == 0) {
            try client.sendFragmented(.binary, &fragments);
            try std.testing.expect(
                client.compression_send.payload.items.len >
                    masked_write_scratch_len,
            );
        } else {
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            client.allocator = failing.allocator();
            defer client.allocator = allocator;
            failing.fail_index = failing.alloc_index;
            try client.sendFragmented(.binary, &fragments);
            try std.testing.expect(!failing.has_induced_failure);
        }
        var response = try client.receiveMessage();
        defer response.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
        try std.testing.expectEqualSlices(u8, &payload, response.payload);
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 uncompressed fragments use bounded send storage" {
    const allocator = std.testing.allocator;
    var payload: [40 * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 131);
    const fragments = [_][]const u8{
        payload[0..9000],
        payload[9000..25_000],
        payload[25_000..],
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = payload.len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = shared.expected.len,
                    .max_message_bytes = shared.expected.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                request.payload,
            );
            try ws.sendFragmented(.binary, &.{
                request.payload[0..9000],
                request.payload[9000..25_000],
                request.payload[25_000..],
            });
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = payload.len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/uncompressed-fragments-bounded",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();

    try client.sendFragmented(.binary, &fragments);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &payload, response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 deadline spans control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        timed_out: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var h2 = try shared.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(
                shared.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                } },
            );
            defer ws.close();
            var storage: [4096]u8 = undefined;
            _ = ws.receiveMessageIntoWithDeadline(
                &storage,
                .fromNow(
                    shared.server.io,
                    .{ .raw = .fromMilliseconds(300), .clock = .awake },
                ),
            ) catch |err| {
                if (err != error.Timeout) return err;
                shared.timed_out = true;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/deadline",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer ws_client.close();
    for (0..2) |_| {
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
        try ws_client.sendPing("keep-http2-busy");
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.timed_out);
}

test "WebSocket receiveFrameAuto replies to ping" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrameAuto();
            defer ping.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("auto?", ping.payload);
            var close = try connection.receiveFrameAuto();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/auto-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("auto?");
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("auto?", pong.payload);
    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithDeadline preserves an interleaved message" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try connection.sendText("in flight");
            try connection.sendPong(ping.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-deadline",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    var application = try client.pingWithDeadline("probe", deadline);
    defer application.deinit(allocator);
    switch (application) {
        .application => |frame| {
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expectEqualStrings("in flight", frame.payload);
        },
        else => return error.TestUnexpectedResult,
    }
    var pong = try client.continuePingWithTimeout(
        "probe",
        .fromSeconds(1),
    );
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout rejects mismatched Pong" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try connection.sendPong("wrong");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/wrong-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectError(
        error.UnexpectedPong,
        client.pingWithTimeout("probe", .fromSeconds(1)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout reports peer Close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try connection.sendClose(.going_away, "maintenance");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    var event = try client.pingWithTimeout("probe", .fromSeconds(1));
    defer event.deinit(allocator);
    switch (event) {
        .closed => |maybe_close| {
            const close = maybe_close orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(websocket.CloseCode.going_away, close.code);
            try std.testing.expectEqualStrings("maintenance", close.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout enforces one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try std.Io.sleep(self.server.http.io, .fromMilliseconds(80), .awake);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-timeout",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout("probe", .fromMilliseconds(20)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP2 pingWithTimeout validates Pong" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                } },
            );
            defer ws.close();
            var ping = try ws.receiveFrame();
            defer ping.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try ws.sendPong(ping.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-ping-timeout",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    var event = try client.pingWithTimeout("h2-probe", .fromSeconds(1));
    defer event.deinit(allocator);
    try std.testing.expect(event == .pong);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveFrameAuto does not pong after sending close" {
    const allocator = std.testing.allocator;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = true,
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, "\x89\x01?");
    var ping = try connection.receiveFrameAuto();
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings("?", ping.payload);

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = true,
    };
    defer h2.inbuf.deinit(allocator);
    try h2.inbuf.appendSlice(allocator, "\x89\x01?");
    var h2_ping = try h2.receiveFrameAuto();
    defer h2_ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, h2_ping.header.opcode);
    try std.testing.expectEqualStrings("?", h2_ping.payload);
}

test "WebSocket runtime exposes typed close frames" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try connection.sendCloseFrame(.{ .code = .going_away, .reason = "restart" });

            var ack = (try connection.receiveCloseFrame()).?;
            defer ack.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.CloseCode.normal_closure, ack.code);
            try std.testing.expectEqualStrings("ack", ack.reason);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/typed-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var close_frame = (try client.receiveCloseFrame()).?;
    defer close_frame.deinit(allocator);
    try std.testing.expectEqual(websocket.CloseCode.going_away, close_frame.code);
    try std.testing.expectEqualStrings("restart", close_frame.reason);
    try client.sendCloseFrame(.{ .code = .normal_closure, .reason = "ack" });

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage assembles fragments and handles control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("hello fragmented", message.payload);

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_received);
            try std.testing.expect(connection.close_sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("?");
    const fragments = [_][]const u8{ "hello ", "fragmented" };
    try client.sendFragmented(.text, &fragments);

    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("?", pong.payload);

    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage enforces aggregate fragmented message limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 12 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try std.testing.expectError(error.PayloadTooLarge, connection.receiveMessage());
            try std.testing.expect(connection.close_sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message-limit",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();

    const fragments = [_][]const u8{ "12345678", "abcdef" };
    try client.sendFragmented(.text, &fragments);

    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqual(
        websocket.CloseCode.message_too_big,
        (try websocket.parseClosePayload(close.payload)).?.code,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage allows in-flight data after initiating close" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try connection.sendClose(.normal_closure, "draining");

            // Like tungstenite, initiating the close handshake only closes our
            // write side.  Data already sent by the peer is still readable
            // until its close acknowledgement arrives.
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("already in flight", message.payload);

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_sent);
            try std.testing.expect(connection.close_received);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/close-after-send",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("already in flight");

    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try client.sendClose(.normal_closure, "ack");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtimes validate outgoing text and close frames" {
    const allocator = std.testing.allocator;
    const bad_utf8 = "\xc0\x80";
    const too_large_control = "x" ** 126;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(error.InvalidUtf8, connection.sendText(bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, connection.sendFragmented(.text, &.{ "\xe2", "(" }));
    try std.testing.expectError(error.InvalidUtf8, connection.sendClose(.normal_closure, bad_utf8));
    try std.testing.expectError(error.InvalidCloseCode, connection.sendClose(.no_status_received, ""));
    try std.testing.expectError(error.InvalidControlFrame, connection.sendPing(too_large_control));
    try std.testing.expectError(error.InvalidFrame, connection.sendFrame(.text, "bypass"));
    try std.testing.expectError(error.InvalidFrame, connection.sendFrame(.continuation, "bypass"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
    };
    try std.testing.expectError(error.InvalidUtf8, h2.sendText(bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, h2.sendFragmented(.text, &.{ "\xf0\x9f", "\x28" }));
    try std.testing.expectError(error.InvalidUtf8, h2.sendClose(.normal_closure, bad_utf8));
    try std.testing.expectError(error.InvalidCloseCode, h2.sendClose(.abnormal_closure, ""));
    try std.testing.expectError(error.InvalidControlFrame, h2.sendPong(too_large_control));
    try std.testing.expectError(error.InvalidFrame, h2.sendFrame(.binary, "bypass"));
    try std.testing.expectError(error.InvalidFrame, h2.sendFrame(.continuation, "bypass"));
}

test "WebSocket incoming message finalization frees failed payloads" {
    const allocator = std.testing.allocator;

    const bad_deflate = try allocator.dupe(u8, &.{ 0xff, 0xff, 0xff });
    try std.testing.expectError(error.InvalidFrame, finishIncomingMessage(allocator, .{
        .opcode = .text,
        .payload = bad_deflate,
        .compressed = true,
    }, 1024));

    const bad_utf8 = try allocator.dupe(u8, "\xc0\x80");
    try std.testing.expectError(error.InvalidUtf8, finishIncomingMessage(allocator, .{
        .opcode = .text,
        .payload = bad_utf8,
        .compressed = false,
    }, 1024));
}

test "WebSocket TCP receive storage uses bounded slab growth" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    const first = [_]u8{0xaa} ** 4104;
    try appendTransportBytesPrecise(&buffer, allocator, &first);
    try std.testing.expectEqual(first.len, buffer.items.len);
    try std.testing.expectEqual(@as(usize, 4352), buffer.capacity);

    buffer.clearRetainingCapacity();
    const small = [_]u8{0xbb} ** 7;
    try appendTransportBytesPrecise(&buffer, allocator, &small);
    try std.testing.expectEqual(@as(usize, 4352), buffer.capacity);

    const extra = [_]u8{0xcc} ** 4098;
    try appendTransportBytesPrecise(&buffer, allocator, &extra);
    try std.testing.expectEqual(small.len + extra.len, buffer.items.len);
    try std.testing.expectEqual(@as(usize, 4352), buffer.capacity);

    buffer.clearRetainingCapacity();
    const large = [_]u8{0xdd} ** 20_001;
    try appendTransportBytesPrecise(&buffer, allocator, &large);
    try std.testing.expectEqual(large.len, buffer.items.len);
    try std.testing.expect(buffer.capacity - large.len < 256);
}

fn checkWebSocketBoundedSlabGrowth(allocator: std.mem.Allocator) !void {
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    try appendTransportBytesPrecise(&buffer, allocator, "header");
    try appendTransportBytesPrecise(&buffer, allocator, "payload");
    try std.testing.expectEqualStrings("headerpayload", buffer.items);
    try std.testing.expect(buffer.capacity - buffer.items.len < 256);
}

test "WebSocket bounded slab growth is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkWebSocketBoundedSlabGrowth,
        .{},
    );
}

test "WebSocket runtimes reject duplicate close sends" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = true,
    };
    try std.testing.expectError(error.ConnectionClosed, connection.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, connection.sendClose(.normal_closure, "again"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = true,
    };
    try std.testing.expectError(error.ConnectionClosed, h2.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, h2.sendClose(.normal_closure, "again"));
}

test "WebSocket send state blocks data after receiving close" {
    try std.testing.expect(!canSendOpcode(.text, false, true));
    try std.testing.expect(!canSendOpcode(.binary, false, true));
    try std.testing.expect(!canSendOpcode(.ping, false, true));
    try std.testing.expect(canSendOpcode(.close, false, true));
    try std.testing.expect(!canSendOpcode(.close, true, true));
}

test "WebSocket runtimes reject frames after received close" {
    const allocator = std.testing.allocator;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, "\x88\x00" ++ "\x81\x02hi");
    var close = try connection.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
    };
    defer h2.inbuf.deinit(allocator);
    try h2.inbuf.appendSlice(allocator, "\x88\x00" ++ "\x81\x02hi");
    var h2_close = try h2.receiveFrame();
    defer h2_close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, h2_close.header.opcode);
    try std.testing.expectError(error.ConnectionClosed, h2.receiveFrame());
}

test "WebSocket runtimes return closed after close handshake completes" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = true,
        .close_received = true,
    };
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = true,
        .close_received = true,
    };
    try std.testing.expectError(error.ConnectionClosed, h2.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, h2.receiveMessage());
}

test "WebSocket async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), connection: *Connection) Error!void {
            var frame = try connection.receiveFrame();
            defer frame.deinit(connection.allocator);
            if (frame.header.opcode != .text) return error.ProtocolFailure;
            if (std.mem.eql(u8, frame.payload, "one")) {
                try connection.sendText("echo-one");
            } else if (std.mem.eql(u8, frame.payload, "two")) {
                try connection.sendText("echo-two");
            } else {
                try connection.sendClose(.unsupported_data, "unexpected");
            }

            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            if (close.header.opcode != .close) return error.ProtocolFailure;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{}) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        payload: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .host = "127.0.0.1",
                .target = "/async",
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer client.close();

            try client.sendText(task.payload);
            var response = try client.receiveFrame();
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
            try std.testing.expectEqualStrings(task.expected, response.payload);
            try client.sendClose(.normal_closure, "bye");
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "one", .expected = "echo-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "two", .expected = "echo-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "WebSocket connection serializes concurrent sends" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn sendOne(connection: *Connection, payload: []const u8, err: *?anyerror) void {
            connection.sendText(payload) catch |e| {
                err.* = e;
            };
        }

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var err_a: ?anyerror = null;
            var err_b: ?anyerror = null;
            const thread_a = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-a", &err_a });
            const thread_b = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-b", &err_b });
            thread_a.join();
            thread_b.join();
            if (err_a) |err| return err;
            if (err_b) |err| return err;

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/send-lock",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var first = try client.receiveFrame();
    defer first.deinit(allocator);
    var second = try client.receiveFrame();
    defer second.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first.header.opcode);
    try std.testing.expectEqual(websocket.Opcode.text, second.header.opcode);
    const saw_a = std.mem.eql(u8, first.payload, "from-a") or std.mem.eql(u8, second.payload, "from-a");
    const saw_b = std.mem.eql(u8, first.payload, "from-b") or std.mem.eql(u8, second.payload, "from-b");
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP upgrade reader enforces header byte limit at delimiter" {
    const exact = "GET /chat HTTP/1.1\r\nHost: example\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, exact.len - 4), try findHttpHeadEndWithinLimit(exact, exact.len));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(exact, exact.len - 1));

    const incomplete = "GET /chat HTTP/1.1\r\nHost: example";
    try std.testing.expectEqual(@as(?usize, null), try findHttpHeadEndWithinLimit(incomplete, incomplete.len + 1));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(incomplete, incomplete.len));
}

test {
    _ = h3;
    _ = @import("runtime/h3_tests.zig");
    _ = @import("runtime/unix_tests.zig");
    _ = @import("runtime/error_close_tests.zig");
    _ = @import("runtime/close_timeout_tests.zig");
    _ = @import("runtime/handshake_timeout_tests.zig");
    _ = @import("runtime/message_io_tests.zig");
    _ = @import("runtime/compression_threshold_tests.zig");
    _ = @import("runtime/wss_tests.zig");
    _ = @import("runtime/server_lifecycle_tests.zig");
}

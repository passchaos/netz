//! Owning gRPC endpoint helpers over the HTTP/2 runtime.
//!
//! The wire/call modules remain transport-agnostic. These wrappers make the
//! production h2c and TLS/ALPN paths available without requiring applications
//! to manually assemble and tear down an HTTP/2 connection for every call.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const auth = @import("auth.zig");
const call = @import("call.zig");
const web = @import("web.zig");
const health = @import("health.zig");
const reflection = @import("reflection.zig");
const service_config = @import("service_config.zig");
const channel = @import("channel.zig");
const streaming = @import("stream/runtime.zig");
const duplex = @import("stream/duplex.zig");

const net = std.Io.net;

pub const Error = web.Error;
pub const Channel = channel.Channel;
pub const ChannelTarget = channel.Target;
pub const ChannelEndpoint = channel.Endpoint;
pub const ChannelSelectionPolicy = channel.SelectionPolicy;
pub const ChannelConnectivityState = channel.ConnectivityState;
pub const ChannelAddressResolver = channel.AddressResolver;
pub const ChannelOptions = channel.Options;
pub const ChannelBackoffPolicy = channel.BackoffPolicy;
pub const ChannelCustomConnector = channel.CustomConnector;

pub const ClientOptions = struct {
    limits: http2.runtime.Limits = .{},
    tls: http2.runtime.TlsConnectOptions = .{},
};

/// One persistent gRPC client channel backed by HTTP/2.
///
/// The channel keeps unary and sequential-stream setup plus teardown in one
/// owner while leaving the HTTP/2 connection public for advanced operations.
/// A single channel must not have concurrent frame readers.
pub const Client = struct {
    connection: http2.runtime.Connection,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: http2.runtime.Limits,
    ) Error!Client {
        return .{ .connection = try http2.runtime.Client.connect(
            allocator,
            io,
            address,
            limits,
        ) };
    }

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ClientOptions,
    ) Error!Client {
        return .{ .connection = try http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            host,
            port,
            options.limits,
            options.tls,
        ) };
    }

    /// Connect to an already resolved address while validating TLS against a
    /// separate DNS name. This keeps service discovery independent from SNI
    /// and certificate identity without weakening verification.
    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        options: ClientOptions,
    ) Error!Client {
        return .{ .connection = try http2.runtime.Client.connectTlsAddress(
            allocator,
            io,
            address,
            tls_host,
            authority,
            options.limits,
            options.tls,
        ) };
    }

    pub fn deinit(self: *Client) void {
        self.connection.close();
        self.* = undefined;
    }

    pub fn unary(
        self: *Client,
        options: call.UnaryCallOptions,
    ) Error!call.UnaryResponse {
        return call.unaryCall(
            &self.connection,
            self.connection.allocator,
            options,
        );
    }

    /// Retry one explicitly replay-safe unary RPC on this persistent channel.
    /// Explicit retries require a configured uncommitted status or reset;
    /// one transparent pre-response refusal recovery remains independent.
    pub fn unaryWithRetry(
        self: *Client,
        options: call.UnaryCallOptions,
        policy: call.RetryPolicy,
    ) Error!call.UnaryResponse {
        return call.unaryCallWithRetry(
            &self.connection,
            self.connection.allocator,
            options,
            policy,
        );
    }

    /// Apply the standard service-config selector for this method. A matching
    /// config without a retry policy disables configured replay while retaining
    /// the caller's transparent refusal-recovery option.
    pub fn unaryWithServiceConfig(
        self: *Client,
        options: call.UnaryCallOptions,
        config: *service_config.ServiceConfig,
    ) Error!call.UnaryResponse {
        const resolved = try config.resolveUnary(options);
        if (resolved.retry_policy) |retry| {
            return self.unaryWithRetry(resolved.options, retry);
        }
        return self.unary(resolved.options);
    }

    pub fn healthCheck(
        self: *Client,
        options: health.CheckOptions,
    ) health.CheckError!health.CheckResult {
        return health.check(
            &self.connection,
            self.connection.allocator,
            options,
        );
    }

    pub fn startHealthWatch(
        self: *Client,
        options: health.WatchOptions,
    ) health.WatchError!health.ClientWatch {
        return health.startWatch(
            &self.connection,
            self.connection.allocator,
            options,
        );
    }

    pub fn startReflection(
        self: *Client,
        options: reflection.ClientOptions,
    ) reflection.StreamError!reflection.ClientSession {
        return reflection.start(
            &self.connection,
            self.connection.allocator,
            options,
        );
    }

    /// Start a sequential gRPC message stream on this persistent channel.
    ///
    /// The returned writer borrows the channel connection and must be
    /// finished or deinitialized before the client is deinitialized or used
    /// to read another stream.
    pub fn startStreaming(
        self: *Client,
        options: streaming.RequestOptions,
    ) streaming.Error!streaming.ClientWriter {
        return streaming.startClient(
            &self.connection,
            self.connection.allocator,
            options,
        );
    }

    /// Apply method timeout and directional message-size policy to a
    /// sequential streaming RPC. Retry policy is intentionally unary-only.
    pub fn startStreamingWithServiceConfig(
        self: *Client,
        options: streaming.RequestOptions,
        config: *service_config.ServiceConfig,
    ) streaming.Error!streaming.ClientWriter {
        return self.startStreaming(
            (try config.resolveStreaming(options)).options,
        );
    }

    /// Start a bidirectional message stream and transfer exclusive connection
    /// read ownership to it.  Do not start another RPC or call a connection
    /// reader until the returned value reaches both terminal halves or is
    /// deinitialized.
    pub fn startDuplex(
        self: *Client,
        options: streaming.RequestOptions,
    ) duplex.Error!duplex.ClientDuplex {
        return duplex.startDuplex(
            &self.connection,
            self.connection.allocator,
            options,
        );
    }

    /// Apply method timeout and directional message-size policy to a duplex
    /// RPC without introducing a second frame reader.
    pub fn startDuplexWithServiceConfig(
        self: *Client,
        options: streaming.RequestOptions,
        config: *service_config.ServiceConfig,
    ) duplex.Error!duplex.ClientDuplex {
        return self.startDuplex(
            (try config.resolveStreaming(options)).options,
        );
    }

    pub fn negotiatedAlpn(self: *const Client) ?[]const u8 {
        return self.connection.negotiatedAlpn();
    }

    pub fn peerCertificates(self: *const Client) ?[]const []const u8 {
        return self.connection.peerCertificates();
    }
};

pub const ServerOptions = struct {
    transport: http2.runtime.TlsListenOptions,
    max_message_size: usize = 16 * 1024 * 1024,
};

/// Cleartext prior-knowledge gRPC listener. The accepted connection has the
/// same unary and streaming surface as `TlsServer`; only transport setup
/// differs.
pub const Server = struct {
    transport: http2.runtime.Server,
    max_message_size: usize,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: http2.runtime.Limits,
        max_message_size: usize,
    ) Error!Server {
        return .{
            .transport = try http2.runtime.Server.listen(
                allocator,
                io,
                bind_address,
                limits,
            ),
            .max_message_size = max_message_size,
        };
    }

    pub fn deinit(self: *Server) void {
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.transport.address();
    }

    pub fn accept(self: *Server) Error!ServerConnection {
        return .{
            .connection = try self.transport.accept(),
            .max_message_size = self.max_message_size,
        };
    }

    pub fn acceptWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) Error!ServerConnection {
        return .{
            .connection = try self.transport.acceptWithTimeout(timeout),
            .max_message_size = self.max_message_size,
        };
    }

    pub fn acceptWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ServerConnection {
        return .{
            .connection = try self.transport.acceptWithDeadline(deadline),
            .max_message_size = self.max_message_size,
        };
    }
};

/// TLS 1.3 gRPC listener with mandatory HTTP/2 ALPN.
///
/// `accept` yields an owning connection wrapper so servers can serve several
/// unary or streaming RPCs on the same channel before deinitialization.
pub const TlsServer = struct {
    transport: http2.runtime.TlsServer,
    max_message_size: usize,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: ServerOptions,
    ) Error!TlsServer {
        return .{
            .transport = try http2.runtime.TlsServer.listen(
                allocator,
                io,
                bind_address,
                options.transport,
            ),
            .max_message_size = options.max_message_size,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn address(self: TlsServer) net.IpAddress {
        return self.transport.address();
    }

    pub fn accept(self: *TlsServer) Error!ServerConnection {
        return .{
            .connection = try self.transport.accept(),
            .max_message_size = self.max_message_size,
        };
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        timeout: std.Io.Duration,
    ) Error!ServerConnection {
        return .{
            .connection = try self.transport.acceptWithTimeout(timeout),
            .max_message_size = self.max_message_size,
        };
    }

    pub fn acceptWithDeadline(
        self: *TlsServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ServerConnection {
        return .{
            .connection = try self.transport.acceptWithDeadline(deadline),
            .max_message_size = self.max_message_size,
        };
    }
};

pub const ServerConnection = struct {
    connection: http2.runtime.Connection,
    max_message_size: usize,

    pub fn deinit(self: *ServerConnection) void {
        self.connection.close();
        self.* = undefined;
    }

    pub fn readUnary(self: *ServerConnection) Error!OwnedUnaryRequest {
        return self.readUnaryMaybeBefore(null);
    }

    pub fn readUnaryWithTimeout(
        self: *ServerConnection,
        timeout: std.Io.Duration,
    ) Error!OwnedUnaryRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readUnaryWithDeadline(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readUnaryWithDeadline(
        self: *ServerConnection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedUnaryRequest {
        return self.readUnaryMaybeBefore(deadline);
    }

    fn readUnaryMaybeBefore(
        self: *ServerConnection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedUnaryRequest {
        var transport = if (deadline) |absolute|
            try self.connection.readRequestWithDeadline(absolute)
        else
            try self.connection.readRequest();
        errdefer transport.deinit(self.connection.allocator);
        const request = call.parseUnaryRequest(
            self.connection.allocator,
            &transport,
            self.max_message_size,
        ) catch |err| {
            self.connection.abandonPeerRequest(
                transport.stream_id,
                .internal_error,
            );
            return err;
        };
        return .{ .transport = transport, .request = request };
    }

    pub fn writeUnary(
        self: *ServerConnection,
        stream_id: u31,
        options: call.UnaryResponseOptions,
    ) Error!void {
        return call.writeUnaryResponse(
            &self.connection,
            self.connection.allocator,
            stream_id,
            options,
        );
    }

    /// Read the next request when the caller has already classified it as
    /// gRPC-Web. Most applications should use `readUnaryWeb`, which performs
    /// the content-type negotiation before dispatch.
    ///
    /// Applications handling browser preflights should use `readWebRequest`.
    pub fn readUnaryWebWith(
        self: *ServerConnection,
        content_type: web.ContentType,
    ) Error!WebUnaryRequest {
        return self.readUnaryWebMaybeBefore(content_type, null);
    }

    pub fn readUnaryWeb(
        self: *ServerConnection,
    ) Error!WebUnaryRequest {
        return self.readUnaryWebMaybeBefore(null, null);
    }

    /// Dispatch one gRPC-Web request, CORS preflight, or HTTP rejection.
    /// Handled streams have already received a response and release peer credit.
    pub fn readWebRequest(self: *ServerConnection, options: web.http2.Options) Error!web.http2.ReadResult {
        return web.http2.readRequest(&self.connection, self.webRequestOptions(options));
    }

    pub fn readWebRequestWithTimeout(self: *ServerConnection, options: web.http2.Options, timeout: std.Io.Duration) Error!web.http2.ReadResult {
        return web.http2.readRequestWithTimeout(&self.connection, self.webRequestOptions(options), timeout);
    }

    pub fn readWebRequestWithDeadline(self: *ServerConnection, options: web.http2.Options, deadline: std.Io.Clock.Timestamp) Error!web.http2.ReadResult {
        return web.http2.readRequestWithDeadline(&self.connection, self.webRequestOptions(options), deadline);
    }

    fn webRequestOptions(self: *const ServerConnection, options: web.http2.Options) web.http2.Options {
        var bounded = options;
        bounded.max_message_size = @min(self.max_message_size, options.max_message_size);
        return bounded;
    }

    pub fn readUnaryWebWithTimeout(
        self: *ServerConnection,
        timeout: std.Io.Duration,
    ) Error!WebUnaryRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readUnaryWebMaybeBefore(
            null,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn readUnaryWebWithDeadline(
        self: *ServerConnection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!WebUnaryRequest {
        return self.readUnaryWebMaybeBefore(null, deadline);
    }

    fn readUnaryWebMaybeBefore(
        self: *ServerConnection,
        preselected_content_type: ?web.ContentType,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!WebUnaryRequest {
        var transport = if (deadline) |absolute|
            try self.connection.readRequestWithDeadline(absolute)
        else
            try self.connection.readRequest();
        errdefer transport.deinit(self.connection.allocator);
        const negotiated = preselected_content_type orelse blk: {
            const raw = call.headerValue(
                transport.headers,
                "content-type",
            ) orelse {
                self.connection.abandonPeerRequest(
                    transport.stream_id,
                    .internal_error,
                );
                return error.InvalidContentType;
            };
            const parsed = web.parseContentType(raw) catch |err| {
                self.connection.abandonPeerRequest(
                    transport.stream_id,
                    .internal_error,
                );
                return err;
            };
            break :blk parsed;
        };
        const response_content_type = web.negotiateResponseContentType(
            negotiated,
            transport.headers,
        ) catch |err| {
            self.connection.abandonPeerRequest(transport.stream_id, .internal_error);
            return err;
        };
        var request = web.parseUnaryRequest(
            self.connection.allocator,
            transport.method,
            transport.path,
            transport.headers,
            transport.body,
            negotiated,
            self.max_message_size,
        ) catch |err| {
            self.connection.abandonPeerRequest(
                transport.stream_id,
                .internal_error,
            );
            return err;
        };
        request.stream_id = transport.stream_id;
        return .{
            .transport = transport,
            .request = request,
            .content_type = response_content_type,
        };
    }

    /// Write one gRPC-Web unary response in the negotiated text or binary
    /// wire. Terminal status travels in the `0x80` body frame (or headers for
    /// a trailers-only response), never as an HTTP trailer block.
    pub fn writeUnaryWeb(
        self: *ServerConnection,
        stream_id: u31,
        options: call.UnaryResponseOptions,
        content_type: web.ContentType,
    ) Error!void {
        return web.writeUnaryResponse(
            &self.connection,
            self.connection.allocator,
            stream_id,
            options,
            content_type,
        );
    }

    /// Require one RFC 6750 Bearer credential before application dispatch.
    /// Rejection is a trailers-only UNAUTHENTICATED response and affects only
    /// this stream, so the HTTP/2 channel remains available for another RPC.
    pub fn requireBearer(
        self: *ServerConnection,
        stream_id: u31,
        headers: []const http2.Hpack.HeaderField,
        expected_token: []const u8,
        status_message: ?[]const u8,
    ) Error!bool {
        if (auth.bearerTokenMatches(headers, expected_token)) return true;
        try self.writeUnary(stream_id, .{
            .status = .unauthenticated,
            .status_message = status_message,
            .trailers_only = true,
        });
        return false;
    }

    pub fn writeHealthCheck(
        self: *ServerConnection,
        registry: *health.Registry,
        request: *const OwnedUnaryRequest,
    ) health.CheckError!void {
        return health.writeCheckResponse(
            &self.connection,
            self.connection.allocator,
            registry,
            &request.request,
        );
    }

    pub fn serveHealthWatch(
        self: *ServerConnection,
        registry: *health.Registry,
        stream: *duplex.ServerDuplex,
    ) (health.WatchError || std.Io.ConcurrentError)!void {
        if (stream.transport.connection != &self.connection) {
            return error.InvalidStreamState;
        }
        return health.serveWatch(stream, registry);
    }

    pub fn serveReflection(
        self: *ServerConnection,
        registry: *reflection.Registry,
        stream: *duplex.ServerDuplex,
    ) reflection.StreamError!void {
        if (stream.transport.connection != &self.connection) {
            return error.InvalidStreamState;
        }
        return reflection.serve(stream, registry);
    }

    /// Read one complete request message stream, delivering messages as their
    /// DATA arrives. The returned request owns its decoded HTTP/2 metadata.
    pub fn readStreaming(
        self: *ServerConnection,
        context: anytype,
        comptime consume: anytype,
    ) !streaming.Request {
        return streaming.readRequest(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            context,
            consume,
        );
    }

    pub fn readStreamingWithTimeout(
        self: *ServerConnection,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !streaming.Request {
        return streaming.readRequestWithTimeout(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            timeout,
            context,
            consume,
        );
    }

    pub fn readStreamingWithDeadline(
        self: *ServerConnection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !streaming.Request {
        return streaming.readRequestWithDeadline(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            deadline,
            context,
            consume,
        );
    }

    /// Accept a bidirectional gRPC call.  The returned value owns the request
    /// metadata and is the connection's sole frame reader until both halves
    /// end or it is deinitialized.
    pub fn acceptDuplex(
        self: *ServerConnection,
    ) duplex.Error!duplex.ServerDuplex {
        return duplex.acceptDuplex(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
        );
    }

    pub fn acceptDuplexWithTimeout(
        self: *ServerConnection,
        timeout: std.Io.Duration,
    ) !duplex.ServerDuplex {
        return duplex.acceptDuplexWithTimeout(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            timeout,
        );
    }

    pub fn acceptDuplexWithDeadline(
        self: *ServerConnection,
        deadline: std.Io.Clock.Timestamp,
    ) !duplex.ServerDuplex {
        return duplex.acceptDuplexWithDeadline(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            deadline,
        );
    }

    /// Read one gRPC-Web server-streaming request. Exactly one framed
    /// request message is delivered to `consume`; the negotiated text/binary
    /// wire is returned for the matching `startStreamingWeb` response.
    pub fn readStreamingWeb(
        self: *ServerConnection,
        context: anytype,
        comptime consume: anytype,
    ) !streaming.WebRequest {
        return streaming.readWebRequest(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            context,
            consume,
        );
    }

    pub fn readStreamingWebWithTimeout(
        self: *ServerConnection,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !streaming.WebRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return streaming.readWebRequestWithTimeout(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            timeout,
            context,
            consume,
        );
    }

    pub fn readStreamingWebWithDeadline(
        self: *ServerConnection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !streaming.WebRequest {
        return streaming.readWebRequestWithDeadline(
            &self.connection,
            self.connection.allocator,
            self.max_message_size,
            deadline,
            context,
            consume,
        );
    }

    /// Start a gRPC-Web server-streaming response. Messages become data
    /// frames and `finish` emits the single `0x80` trailers frame.
    pub fn startStreamingWeb(
        self: *ServerConnection,
        stream_id: u31,
        options: web.StreamResponseOptions,
        content_type: web.ContentType,
    ) !web.ServerStreamWriter {
        return web.startServerStream(
            &self.connection,
            self.connection.allocator,
            stream_id,
            options,
            content_type,
        );
    }

    /// Start a message-stream response for a request returned by
    /// `readStreaming`. The writer borrows this connection until it is
    /// finished or deinitialized.
    pub fn startStreamingResponse(
        self: *ServerConnection,
        stream_id: u31,
        options: streaming.ResponseOptions,
    ) streaming.Error!streaming.ServerWriter {
        return streaming.startResponse(
            &self.connection,
            self.connection.allocator,
            stream_id,
            options,
        );
    }

    pub fn negotiatedAlpn(self: *const ServerConnection) ?[]const u8 {
        return self.connection.negotiatedAlpn();
    }

    pub fn peerCertificates(
        self: *const ServerConnection,
    ) ?[]const []const u8 {
        return self.connection.peerCertificates();
    }
};

/// Owns both the HTTP/2 header/body storage and any separately decompressed
/// gRPC message. `request` borrows metadata slices from `transport`, so the two
/// values intentionally share one lifetime.
pub const OwnedUnaryRequest = struct {
    transport: http2.runtime.OwnedRequest,
    request: call.UnaryRequest,

    pub fn deinit(self: *OwnedUnaryRequest) void {
        const allocator = self.request.allocator;
        self.request.deinit();
        self.transport.deinit(allocator);
        self.* = undefined;
    }
};

/// One accepted unary gRPC-Web RPC plus the negotiated text/binary wire the
/// matching `writeUnaryWeb` response must use.
pub const WebUnaryRequest = struct {
    transport: http2.runtime.OwnedRequest,
    request: call.UnaryRequest,
    content_type: web.ContentType,

    pub fn deinit(self: *WebUnaryRequest) void {
        const allocator = self.request.allocator;
        self.request.deinit();
        self.transport.deinit(allocator);
        self.* = undefined;
    }
};

//! Owning gRPC endpoint helpers over the HTTP/2 runtime.
//!
//! The wire/call modules remain transport-agnostic. These wrappers make the
//! production h2c and TLS/ALPN paths available without requiring applications
//! to manually assemble and tear down an HTTP/2 connection for every call.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const call = @import("call.zig");
const health = @import("health.zig");
const streaming = @import("stream/runtime.zig");
const duplex = @import("stream/duplex.zig");

const net = std.Io.net;

pub const Error = call.Error;

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
};

pub const ServerConnection = struct {
    connection: http2.runtime.Connection,
    max_message_size: usize,

    pub fn deinit(self: *ServerConnection) void {
        self.connection.close();
        self.* = undefined;
    }

    pub fn readUnary(self: *ServerConnection) Error!OwnedUnaryRequest {
        var transport = try self.connection.readRequest();
        errdefer transport.deinit(self.connection.allocator);
        const request = try call.parseUnaryRequest(
            self.connection.allocator,
            &transport,
            self.max_message_size,
        );
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

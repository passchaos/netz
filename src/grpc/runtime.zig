//! Owning gRPC endpoint helpers over the HTTP/2 runtime.
//!
//! The wire/call modules remain transport-agnostic. These wrappers make the
//! production h2c and TLS/ALPN paths available without requiring applications
//! to manually assemble and tear down an HTTP/2 connection for every call.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const call = @import("call.zig");

const net = std.Io.net;

pub const Error = call.Error;

pub const ClientOptions = struct {
    limits: http2.runtime.Limits = .{},
    tls: http2.runtime.TlsConnectOptions = .{},
};

/// One persistent gRPC client channel backed by HTTP/2.
///
/// The channel intentionally exposes its HTTP/2 connection for advanced
/// streaming calls while keeping unary setup, URI authority, and teardown in
/// one owner. A single channel must not have concurrent frame readers.
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

//! HTTP/1 client connection, request writers, and response readers.

const std = @import("std");
const http1 = @import("../mod.zig");
const net = std.Io.net;
const socket_address = @import("../../internal/socket_address.zig");
const runtime = @import("../runtime.zig");

const ConnectIpSession = runtime.ConnectIpSession;
const ConnectUdpSession = runtime.ConnectUdpSession;
const ConnectUdpTunnel = runtime.ConnectUdpTunnel;
const Connection = runtime.Connection;
const Error = runtime.Error;
const InformationalObserver = runtime.InformationalObserver;
const Limits = runtime.Limits;
const OwnedResponse = runtime.OwnedResponse;
const PreparedForwardProxyRequest = runtime.PreparedForwardProxyRequest;
const ProxyOptions = runtime.ProxyOptions;
const RedirectOptions = runtime.RedirectOptions;
const RedirectedResponse = runtime.RedirectedResponse;
const RequestOptions = runtime.RequestOptions;
const RequestWriter = runtime.RequestWriter;
const RuntimeTransport = runtime.RuntimeTransport;
const StreamingBodyReader = runtime.StreamingBodyReader;
const StreamingBodyWriter = runtime.StreamingBodyWriter;
const StreamingRequestOptions = runtime.StreamingRequestOptions;
const StreamingResponse = runtime.StreamingResponse;
const TlsClientConnection = runtime.TlsClientConnection;
const TlsClientOptions = runtime.TlsClientOptions;
const Tunnel = runtime.Tunnel;
const VailTlsClientOptions = runtime.VailTlsClientOptions;
const WriteScratch = runtime.WriteScratch;
const body_writer = runtime.body_writer;
const clientReadHeadSome = runtime.clientReadHeadSome;
const clientReadSome = runtime.clientReadSome;
const clientWriteSlices = runtime.clientWriteSlices;
const connectTunnelViaProxyBefore = runtime.connectTunnelViaProxyBefore;
const deadline_policy = runtime.deadline_policy;
const ensureResponseHeadDeadlineForBuffer = runtime.ensureResponseHeadDeadlineForBuffer;
const flattenWriteParts = runtime.flattenWriteParts;
const http3 = runtime.http3;
const ignoreStreamingResponseHead = runtime.ignoreStreamingResponseHead;
const message_reuse = runtime.message_reuse;
const probeIdleSocket = runtime.probeIdleSocket;
const readResponseFromTransportBufferedForRequestObserved = runtime.readResponseFromTransportBufferedForRequestObserved;
const redirectHeaders = runtime.redirectHeaders;
const rejectUpgradeManagedHeaders = runtime.rejectUpgradeManagedHeaders;
const requestOptionsKeepAlive = runtime.requestOptionsKeepAlive;
const requestShouldSendContinue = runtime.requestShouldSendContinue;
const requestUriViaProxyBefore = runtime.requestUriViaProxyBefore;
const responseIsReusable = runtime.responseIsReusable;
const runtime_write = runtime.runtime_write;
const setTcpNoDelay = runtime.setTcpNoDelay;
const stream_io = runtime.stream_io;
const streamingResponseFromReader = runtime.streamingResponseFromReader;
const streamingResponseIsReusable = runtime.streamingResponseIsReusable;
const tcp_connect = runtime.tcp_connect;
const tls = runtime.tls;
const tls_stream = runtime.tls_stream;
const uriEndpoint = runtime.uriEndpoint;
const uriTargetAlloc = runtime.uriTargetAlloc;
const uri_redirect = runtime.uri_redirect;
const vail = runtime.vail;
const validateUpgradeProtocol = runtime.validateUpgradeProtocol;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const writeMessagePartsWithStrategy = runtime.writeMessagePartsWithStrategy;

pub const Client = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    write_scratch: WriteScratch = .{},
    writer_state: body_writer.State = .{},
    default_host: ?[]u8 = null,
    tls_conn: ?*TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    response_head_deadline: ?std.Io.Clock.Timestamp = null,
    response_deadline: ?std.Io.Clock.Timestamp = null,
    response_head_sequence_active: bool = false,

    /// Adopt an already connected cleartext stream. Ownership transfers at
    /// entry and every failure closes the stream. The authority is copied for
    /// later requests that omit Host.
    pub fn adoptStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        authority: []const u8,
        limits: Limits,
    ) Error!Client {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (authority.len == 0) return error.InvalidHost;
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const owned_authority = try allocator.dupe(u8, authority);
        stream_owned = false;
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_authority,
        };
    }

    /// Perform an origin-authenticated TLS handshake on a caller-connected
    /// tunnel, then adopt it as an HTTP/1 client. Ownership of `stream`
    /// transfers at entry on every outcome.
    pub fn adoptTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!Client {
        return adoptTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            authority,
            limits,
            tls_options,
            null,
        );
    }

    pub fn adoptTlsStreamWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        return adoptTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            authority,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn adoptTlsStreamWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) {
            stream.close(io);
            return error.Timeout;
        }
        return adoptTlsStreamWithDeadline(
            allocator,
            io,
            stream,
            tls_host,
            authority,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn adoptTlsStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Client {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (authority.len == 0) return error.InvalidHost;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(io, absolute);
        }
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = if (deadline) |absolute|
            try TlsClientConnection.initWithDeadline(
                allocator,
                io,
                stream,
                tls_host,
                tls_options,
                absolute,
            )
        else
            try TlsClientConnection.init(
                allocator,
                io,
                stream,
                tls_host,
                tls_options,
            );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_authority = try allocator.dupe(u8, authority);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_authority,
            .tls_conn = tls_conn,
        };
    }

    /// Adopt a certificate-verified vail TLS connection whose ALPN result is
    /// compatible with HTTP/1.1. A missing ALPN is accepted for legacy HTTPS;
    /// any selected protocol other than `http/1.1` fails closed. Ownership of
    /// `tls_connection` transfers at entry.
    pub fn adoptNegotiatedTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        tls_connection: *tls_stream.ClientConnection,
        authority: []const u8,
        limits: Limits,
    ) Error!Client {
        var tls_owned = true;
        errdefer if (tls_owned) tls_connection.deinit();
        if (authority.len == 0) return error.InvalidHost;
        if (tls_connection.negotiatedAlpn()) |alpn| {
            if (!std.mem.eql(u8, alpn, "http/1.1")) {
                return error.InvalidAlpn;
            }
        }
        if (limits.tcp_nodelay) try setTcpNoDelay(tls_connection.stream);
        const owned_authority = try allocator.dupe(u8, authority);
        tls_owned = false;
        return .{
            .io = io,
            .allocator = allocator,
            .stream = tls_connection.stream,
            .limits = limits,
            .default_host = owned_authority,
            .tls_vail_conn = tls_connection,
        };
    }

    pub fn transport(self: *Client) RuntimeTransport {
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls_client = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    /// Remote transport IP peer. Unix streams and unavailable native queries
    /// return null; proxy tunnels report the connected proxy, not the origin.
    pub fn peerAddress(self: *const Client) ?net.IpAddress {
        return socket_address.connected(self.stream);
    }

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Client {
        const stream = try tcp_connect.ip(io, address, limits.connect_timeout);
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
        };
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
        };
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            address,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect over a Unix-domain socket while retaining ordinary HTTP/1 Host
    /// semantics. `host` is copied because later requests may omit it and use
    /// the connection default. TCP_NODELAY is deliberately not applied.
    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        host: []const u8,
        limits: Limits,
    ) Error!Client {
        if (host.len == 0) return error.InvalidHost;
        const stream = try tcp_connect.unix(io, address, limits.connect_timeout);
        errdefer stream.close(io);
        const owned_host = try allocator.dupe(u8, host);
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        host: []const u8,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        if (host.len == 0) return error.InvalidHost;
        const stream = try tcp_connect.unixWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        const owned_host = try allocator.dupe(u8, host);
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn connectUnixWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        host: []const u8,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithDeadline(
            allocator,
            io,
            address,
            host,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const owned_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        errdefer allocator.free(owned_host);
        const stream = try tcp_connect.host(io, host_name, port, limits.connect_timeout);
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    /// Resolve a hostname and connect under a caller-owned awake-clock
    /// deadline. A configured connect timeout can only shorten that budget.
    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const owned_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ host, port },
        );
        errdefer allocator.free(owned_host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(
            allocator,
            io,
            host,
            port,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(io, host_name, port, limits.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.init(allocator, io, stream, host, tls_options);
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
            .tls_conn = tls_conn,
        };
    }

    /// Share one absolute deadline across DNS/TCP and the TLS handshake while
    /// retaining stricter connect and TLS phase limits.
    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.initWithDeadline(
            allocator,
            io,
            stream,
            host,
            tls_options,
            deadline,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ host, port },
        );
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
            .tls_conn = tls_conn,
        };
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!Client {
        const stream = try tcp_connect.ip(io, address, limits.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.init(
            allocator,
            io,
            stream,
            tls_host,
            tls_options,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_authority = try allocator.dupe(u8, authority);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_authority,
            .tls_conn = tls_conn,
        };
    }

    pub fn connectTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.initWithDeadline(
            allocator,
            io,
            stream,
            tls_host,
            tls_options,
            deadline,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_authority = try allocator.dupe(u8, authority);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_authority,
            .tls_conn = tls_conn,
        };
    }

    pub fn connectTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            authority,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectVailTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(io, host_name, port, limits.connect_timeout);
        return connectVailTlsStream(
            allocator,
            io,
            stream,
            host,
            port,
            limits,
            tls_options,
        );
    }

    pub fn connectVailTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        return connectVailTlsStreamBefore(
            allocator,
            io,
            stream,
            host,
            port,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectVailTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectVailTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectVailTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!Client {
        const stream = try tcp_connect.ip(io, address, limits.connect_timeout);
        const port = switch (address) {
            .ip4 => |ip4| ip4.port,
            .ip6 => |ip6| ip6.port,
        };
        return connectVailTlsStream(
            allocator,
            io,
            stream,
            tls_host,
            port,
            limits,
            tls_options,
        );
    }

    pub fn connectVailTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        return connectVailTlsStreamBefore(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectVailTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectVailTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectVailTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!Client {
        return connectVailTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            limits,
            tls_options,
            null,
        );
    }

    fn connectVailTlsStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectVailTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            limits,
            tls_options,
            deadline,
        );
    }

    fn connectVailTlsStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Client {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const options = verifiedTlsClientOptions(tls_host, tls_options);
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ClientConnection.initVerifiedWithDeadline(
                allocator,
                io,
                stream,
                options,
                absolute,
            )
        else
            try tls_stream.ClientConnection.initVerified(
                allocator,
                io,
                stream,
                options,
            );
        stream_owned = false;
        errdefer tls_connection.deinit();
        // HTTP/1.1 cannot run over a connection that negotiated another
        // protocol. A missing ALPN stays accepted for legacy HTTPS origins.
        if (tls_connection.negotiatedAlpn()) |alpn| {
            if (!std.mem.eql(u8, alpn, "http/1.1")) return error.InvalidAlpn;
        }
        const owned_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ tls_host, port },
        );
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
            .tls_vail_conn = tls_connection,
        };
    }

    pub fn close(self: *Client) void {
        if (self.default_host) |host| self.allocator.free(host);
        self.inbuf.deinit(self.allocator);
        self.write_scratch.deinit(self.allocator);
        if (self.tls_conn) |conn| {
            conn.deinit();
        } else if (self.tls_vail_conn) |conn| {
            conn.deinit();
        } else {
            self.stream.close(self.io);
        }
        self.* = undefined;
    }

    /// Retire a completed/closed-pool lease without writing TLS shutdown.
    pub fn closeWithoutCloseNotify(self: *Client) void {
        if (self.tls_conn) |conn| conn.write_closed = true;
        if (self.tls_vail_conn) |conn| {
            self.tls_vail_conn = null;
            conn.deinitWithoutCloseNotify();
            // The TLS connection already owns and closes the socket.
            if (self.default_host) |host| self.allocator.free(host);
            self.inbuf.deinit(self.allocator);
            self.write_scratch.deinit(self.allocator);
            self.* = undefined;
        } else self.close();
    }

    /// Attempt a bounded TLS shutdown and release the transport even if its
    /// alert could not finish. Pool close accounts this resource exactly once.
    pub fn closeWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!void {
        defer self.closeWithoutCloseNotify();
        if (self.tls_vail_conn) |connection| {
            try connection.sendCloseNotifyWithDeadline(deadline);
        } else if (self.tls_conn) |connection| {
            if (connection.write_closed) return;
            if (connection.pending_timed_plaintext_len != 0 or connection.net_writer.interface.buffered().len != 0 or connection.client.writer.buffered().len != 0) return error.WriteInProgress;
            try connection.client.end();
            while (connection.net_writer.interface.buffered().len != 0) {
                const n = try stream_io.writeSomeWithDeadline(connection.io, connection.stream, connection.net_writer.interface.buffered(), deadline);
                _ = connection.net_writer.interface.consume(n);
            }
            connection.write_closed = true;
        }
    }

    /// Convenience form of `closeWithDeadline` using an awake-clock budget.
    /// An expired budget still retires the transport, matching the deadline
    /// form's no-output cleanup contract.
    pub fn closeWithTimeout(self: *Client, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) {
            self.closeWithoutCloseNotify();
            return error.Timeout;
        }
        return self.closeWithDeadline(.fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn peerCertificates(
        self: *const Client,
    ) ?[]const []const u8 {
        const connection = self.tls_vail_conn orelse return null;
        return connection.peerCertificates();
    }

    pub fn negotiatedAlpn(self: *const Client) ?[]const u8 {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedAlpn();
    }

    pub fn negotiatedTlsProtocol(
        self: *const Client,
    ) ?tls_stream.Protocol {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedProtocol();
    }

    pub fn wasTlsSessionResumed(self: *const Client) ?bool {
        const connection = self.tls_vail_conn orelse return null;
        return connection.wasResumed();
    }

    pub fn takeTls12SessionTicket(
        self: *Client,
    ) ?tls_stream.Tls12SessionTicket {
        const connection = self.tls_vail_conn orelse return null;
        return connection.takeTls12SessionTicket();
    }

    pub fn takeTls13SessionTicket(
        self: *Client,
    ) tls_stream.Error!?tls_stream.Tls13SessionTicket {
        const connection = self.tls_vail_conn orelse return null;
        return connection.takeTls13SessionTicket();
    }

    pub fn negotiatedCipherSuite(
        self: *const Client,
    ) ?tls_stream.NegotiatedCipherSuite {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: *const Client,
    ) ?tls_stream.TranscriptHash {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedTranscriptHash();
    }

    pub fn exportKeyingMaterial(
        self: *const Client,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        const connection = self.tls_vail_conn orelse
            return error.PostHandshakeTlsUnavailable;
        try connection.exportKeyingMaterial(label, context, out);
    }

    pub fn updateTrafficKeys(
        self: *Client,
        request_peer_update: bool,
    ) Error!void {
        const connection = self.tls_vail_conn orelse
            return error.PostHandshakeTlsUnavailable;
        try self.writer_state.ensureAvailable();
        connection.updateTrafficKeys(request_peer_update) catch |err| {
            switch (err) {
                error.WriteInProgress, error.KeyUpdateRequestPending => {},
                else => self.writer_state.phase = .unusable,
            }
            return err;
        };
    }

    pub fn keyUpdateCounts(
        self: *const Client,
    ) ?tls_stream.KeyUpdateCounts {
        const connection = self.tls_vail_conn orelse return null;
        return connection.keyUpdateCounts();
    }

    pub fn isReusable(self: *const Client) bool {
        return self.writer_state.phase == .idle and
            !self.writer_state.reading and
            self.inbuf.items.len == 0;
    }

    /// Reject clients that retain unread HTTP or TLS input. Cleartext sockets
    /// additionally probe the kernel queue for unsolicited bytes or EOF. TLS
    /// records still in the kernel cannot be classified without advancing the
    /// decryptor, so only already-buffered TLS state is inspected. Unsupported
    /// native backends conservatively skip the cleartext socket probe.
    pub fn isReusableForPool(self: *const Client) bool {
        if (!self.isReusable()) return false;
        if (self.tls_conn) |connection| {
            return connection.isReusableBoundary();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.isReusableBoundary();
        }
        return probeIdleSocket(self.stream) == .clean;
    }

    /// Validate and encode before touching the transport. Once a complete
    /// request write starts, any transport error is terminal: the peer may
    /// have observed an arbitrary prefix and HTTP/1 has no stream reset with
    /// which to restore the message boundary.
    pub fn writeRequestFailClosed(
        self: *Client,
        options: RequestOptions,
    ) Error!void {
        const parts = try runtime_write.prepareRequest(
            self.allocator,
            options,
            &self.write_scratch,
        );
        if (self.response_deadline) |deadline| {
            var committed: usize = 0;
            const active_transport = self.transport();
            if (self.limits.write_strategy == .flatten) {
                const bytes = try flattenWriteParts(
                    self.allocator,
                    &self.write_scratch,
                    &.{ parts.header, parts.body },
                );
                active_transport.writeAllWithDeadline(
                    bytes,
                    &committed,
                    deadline,
                ) catch |err| {
                    self.writer_state.phase = .unusable;
                    return err;
                };
            } else active_transport.writeAllPartsWithDeadline(
                parts.header,
                parts.body,
                &committed,
                deadline,
            ) catch |err| {
                // TLS may have consumed a sequence number into a buffered
                // record even when no complete plaintext prefix committed.
                // Once a timed transport write starts, retire the HTTP
                // connection rather than risk replaying an ambiguous prefix.
                self.writer_state.phase = .unusable;
                return err;
            };
            return;
        }
        var transport_started = false;
        writeMessagePartsWithStrategy(
            self.allocator,
            self.transport(),
            self.limits.write_strategy,
            parts,
            &self.write_scratch,
            &transport_started,
        ) catch |err| {
            if (transport_started) self.writer_state.phase = .unusable;
            return err;
        };
    }

    pub fn request(self: *Client, request_options: RequestOptions) Error!OwnedResponse {
        return self.requestWithParseOptions(
            request_options,
            .{},
        );
    }

    /// Send a complete request with explicit response parser compatibility.
    pub fn requestWithParseOptions(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformational(
            request_options,
            parse_options,
            null,
        );
    }

    pub fn requestWithParseOptionsAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithParseOptionsAndDeadline(
            request_options,
            parse_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestWithParseOptionsAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformationalAndDeadline(
            request_options,
            parse_options,
            null,
            deadline,
        );
    }

    pub fn requestWithParseOptionsAndInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithParseOptionsAndInformationalAndDeadline(
            request_options,
            parse_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Bound the complete response, including its body and trailers, with one
    /// absolute awake-clock budget. The existing response-head timeout remains
    /// active and whichever deadline expires first wins. HTTP/1 has no stream
    /// reset, so any read failure after the request write marks the connection
    /// unusable through the ordinary request error path.
    pub fn requestWithTimeout(
        self: *Client,
        request_options: RequestOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(
            request_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestWithDeadline(
        self: *Client,
        request_options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.requestWithInformationalAndDeadline(
            request_options,
            null,
            deadline,
        );
    }

    /// Observe interim responses while bounding the request write and complete
    /// response with one caller-owned deadline.
    pub fn requestWithInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformationalAndDeadline(
            request_options,
            .{},
            informational,
            deadline,
        );
    }

    pub fn requestWithParseOptionsAndInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestWithParseOptionsAndInformational(
            request_options,
            parse_options,
            informational,
        );
    }

    pub fn requestWithInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Send a complete request and observe each valid interim response before
    /// returning the final response. The observer borrows parser storage only
    /// for the callback duration.
    pub fn requestWithInformational(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformational(
            request_options,
            .{},
            informational,
        );
    }

    pub fn requestWithParseOptionsAndInformational(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        const generation = try self.writer_state.begin();
        _ = generation;
        errdefer if (self.writer_state.phase == .writing) {
            // Local request validation can fail before any byte reaches the
            // transport. Preserve the caller's ability to correct and retry.
            self.writer_state.phase = .idle;
        };
        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        try self.writeRequestFailClosed(options);
        self.writer_state.phase = .awaiting_peer;
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        const response = readResponseFromTransportBufferedForRequestObserved(
            self.allocator,
            self.transport(),
            self.limits,
            parse_options,
            &self.inbuf,
            request_options.method,
            informational,
            null,
            self.response_deadline,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        self.writer_state.phase = if (requestOptionsKeepAlive(options) and
            responseIsReusable(response.response, request_options.method))
            .idle
        else
            .unusable;
        return response;
    }

    /// Send a complete request and receive response body slices incrementally.
    ///
    /// The returned head/trailers are owned. Each body slice borrows reusable
    /// connection storage and is valid only until `consume` returns.
    pub fn requestStreaming(
        self: *Client,
        request_options: RequestOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithHead(
            request_options,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithTimeout(
        self: *Client,
        request_options: RequestOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithDeadline(
            request_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn requestStreamingWithDeadline(
        self: *Client,
        request_options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndDeadline(
            request_options,
            null,
            deadline,
            context,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreamingWithInformational(
            request_options,
            informational,
            context,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Streaming response counterpart that enables explicit parser
    /// compatibility options, including obsolete line folding in trailers.
    pub fn requestStreamingWithParseOptions(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndInformational(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithParseOptionsAndDeadline(
            request_options,
            parse_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithParseOptionsAndInformationalAndDeadline(
            request_options,
            parse_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    /// Stream a response body while observing informational and final heads.
    pub fn requestStreamingWithInformational(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHead(
            request_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithHead(
        self: *Client,
        request_options: RequestOptions,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHead(
            request_options,
            null,
            context,
            begin,
            consume,
        );
    }

    /// Streaming response receive with ordered observation of preceding 1xx
    /// heads. Informational callbacks run before the final-head callback.
    pub fn requestStreamingWithInformationalAndHead(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            .{},
            informational,
            context,
            begin,
            consume,
        );
    }

    pub fn requestStreamingWithOptionsAndHead(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        const generation = try self.writer_state.begin();
        _ = generation;
        errdefer if (self.writer_state.phase == .writing) {
            self.writer_state.phase = .idle;
        };
        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        const parts = try runtime_write.prepareRequest(
            self.allocator,
            options,
            &self.write_scratch,
        );
        var transport_started = false;
        writeMessagePartsWithStrategy(
            self.allocator,
            self.transport(),
            self.limits.write_strategy,
            parts,
            &self.write_scratch,
            &transport_started,
        ) catch |err| {
            if (transport_started) self.writer_state.phase = .unusable;
            return err;
        };
        self.writer_state.phase = .awaiting_peer;
        const response = try self.readStreamingResponse(
            request_options.method,
            parse_options,
            informational,
            null,
            context,
            begin,
            consume,
        );
        self.writer_state.phase =
            if (requestOptionsKeepAlive(options) and
            streamingResponseIsReusable(
                response,
                request_options.method,
            ))
                .idle
            else
                .unusable;
        return response;
    }

    /// Start a request whose body is supplied incrementally.
    ///
    /// HTTP/1 serializes exchanges on a connection. The returned writer owns
    /// that slot through body completion and response receive; abandoning it
    /// makes the connection unusable because HTTP/1 has no per-message reset.
    pub fn startRequest(
        self: *Client,
        request_options: StreamingRequestOptions,
    ) Error!RequestWriter {
        return self.startRequestUntil(request_options, null);
    }

    /// Bound request-head setup; later body and response operations choose
    /// their own deadlines on the returned writer.
    pub fn startRequestWithDeadline(self: *Client, options: StreamingRequestOptions, deadline: std.Io.Clock.Timestamp) Error!RequestWriter {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.startRequestUntil(options, deadline);
    }

    pub fn startRequestWithTimeout(self: *Client, options: StreamingRequestOptions, timeout: std.Io.Duration) Error!RequestWriter {
        return self.startRequestWithDeadline(options, (try deadline_policy.fromTimeout(self.io, timeout)).?);
    }

    fn startRequestUntil(self: *Client, request_options: StreamingRequestOptions, deadline: ?std.Io.Clock.Timestamp) Error!RequestWriter {
        const generation = try self.writer_state.begin();
        errdefer if (self.writer_state.phase == .writing) {
            self.writer_state.phase = .idle;
        };

        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        const prepared = try runtime_write.streaming.prepareRequest(
            self.allocator,
            options,
            &self.write_scratch,
        );
        const announced_trailers = self.write_scratch.trailerHeaders();
        var committed: usize = 0;
        const output = if (deadline) |absolute|
            self.transport().writeAllWithDeadline(prepared.head, &committed, absolute)
        else
            self.transport().writeAll(prepared.head);
        output catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        return .{
            .client = self,
            .method = options.method,
            .expects_continue = requestShouldSendContinue(prepared.head),
            .body = StreamingBodyWriter.initWithDeadline(
                self.allocator,
                &self.writer_state,
                generation,
                self,
                clientWriteSlices,
                &self.write_scratch,
                prepared,
                announced_trailers,
                false,
                self.io,
                @import("writer_output.zig").client,
            ),
        };
    }

    /// Send one absolute-form request over an already connected HTTP proxy.
    /// The target URI must use `http`; HTTPS uses CONNECT plus TLS through the
    /// one-shot `requestUriViaProxy*` helpers below. Proxy-only headers are
    /// appended after origin request fields and participate in ordinary
    /// duplicate/framing validation before any bytes are written.
    pub fn requestForwardProxyUri(
        self: *Client,
        uri_text: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
    ) Error!OwnedResponse {
        var prepared = try PreparedForwardProxyRequest.init(
            self.allocator,
            uri_text,
            request_options,
            proxy_options,
        );
        defer prepared.deinit();
        return self.request(prepared.options);
    }

    pub fn requestForwardProxyUriWithDeadline(
        self: *Client,
        uri_text: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var prepared = try PreparedForwardProxyRequest.init(
            self.allocator,
            uri_text,
            request_options,
            proxy_options,
        );
        defer prepared.deinit();
        return self.requestWithDeadline(prepared.options, deadline);
    }

    pub fn requestForwardProxyUriWithTimeout(
        self: *Client,
        uri_text: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestForwardProxyUriWithDeadline(
            uri_text,
            request_options,
            proxy_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Establish a raw TCP tunnel through a cleartext HTTP proxy and transfer
    /// ownership to the caller. CONNECT response parsing must end at an empty
    /// boundary; any suffix is rejected because it arrived before the upper
    /// protocol could send its first bytes and cannot be authenticated.
    pub fn connectTunnelViaProxyUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        target: []const u8,
        proxy_options: ProxyOptions,
        limits: Limits,
    ) Error!net.Stream {
        return connectTunnelViaProxyBefore(
            allocator,
            io,
            proxy_uri,
            target,
            proxy_options,
            limits,
            null,
        );
    }

    pub fn connectTunnelViaProxyUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        target: []const u8,
        proxy_options: ProxyOptions,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!net.Stream {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectTunnelViaProxyBefore(
            allocator,
            io,
            proxy_uri,
            target,
            proxy_options,
            limits,
            deadline,
        );
    }

    pub fn connectTunnelViaProxyUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        target: []const u8,
        proxy_options: ProxyOptions,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!net.Stream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTunnelViaProxyUriWithDeadline(
            allocator,
            io,
            proxy_uri,
            target,
            proxy_options,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Perform a one-shot HTTP or HTTPS origin request through a cleartext
    /// HTTP proxy. HTTP uses absolute-form directly. HTTPS sends CONNECT,
    /// validates an empty successful response, then authenticates the origin
    /// over TLS on the same byte stream before sending an origin-form request.
    pub fn requestUriViaProxy(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        target_uri: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!OwnedResponse {
        return requestUriViaProxyBefore(
            allocator,
            io,
            proxy_uri,
            target_uri,
            request_options,
            proxy_options,
            limits,
            tls_options,
            null,
        );
    }

    pub fn requestUriViaProxyWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        target_uri: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(io, deadline);
        return requestUriViaProxyBefore(
            allocator,
            io,
            proxy_uri,
            target_uri,
            request_options,
            proxy_options,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn requestUriViaProxyWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        target_uri: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriViaProxyWithDeadline(
            allocator,
            io,
            proxy_uri,
            target_uri,
            request_options,
            proxy_options,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Follow bounded HTTP/HTTPS redirects and return the final response.
    /// Relative Location values use RFC 3986 resolution. HTTPS-to-HTTP
    /// downgrade and cross-origin credential forwarding are denied by default.
    /// A configured proxy is reused through a fresh request/CONNECT per hop.
    pub fn requestUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
    ) Error!OwnedResponse {
        var result = try requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            redirect_options,
            null,
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailed(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
    ) Error!RedirectedResponse {
        return requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            redirect_options,
            null,
        );
    }

    /// Retain one absolute caller budget across all DNS/TCP, proxy CONNECT,
    /// TLS, request writes, response entities, and redirect decisions.
    pub fn requestUriFollowingRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        var result = try requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailedWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!RedirectedResponse {
        return requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn requestUriFollowingRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriFollowingRedirectsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriFollowingRedirectsDetailedWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) Error!RedirectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriFollowingRedirectsDetailedWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn requestUriFollowingRedirectsDetailedBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!RedirectedResponse {
        var chain = uri_redirect.Chain.init(
            allocator,
            redirect_options.policy,
        );
        defer chain.deinit();
        try chain.recordInitial(uri_text);
        var current_uri = try allocator.dupe(u8, uri_text);
        defer allocator.free(current_uri);
        var hop_options = request_options;
        var owned_headers: ?[]http1.Header = null;
        defer if (owned_headers) |headers| allocator.free(headers);

        while (true) {
            var response = if (redirect_options.proxy) |proxy|
                if (deadline) |absolute|
                    try requestUriViaProxyWithDeadline(
                        allocator,
                        io,
                        proxy.uri,
                        current_uri,
                        hop_options,
                        proxy.options,
                        limits,
                        redirect_options.tls,
                        absolute,
                    )
                else
                    try requestUriViaProxy(
                        allocator,
                        io,
                        proxy.uri,
                        current_uri,
                        hop_options,
                        proxy.options,
                        limits,
                        redirect_options.tls,
                    )
            else if (deadline) |absolute|
                try requestUriTlsWithDeadline(
                    allocator,
                    io,
                    current_uri,
                    hop_options,
                    limits,
                    redirect_options.tls,
                    absolute,
                )
            else
                try requestUriTls(
                    allocator,
                    io,
                    current_uri,
                    hop_options,
                    limits,
                    redirect_options.tls,
                );
            errdefer response.deinit(allocator);
            if (!uri_redirect.isRedirectStatus(response.response.status)) {
                return .{
                    .allocator = allocator,
                    .response = response,
                    .final_uri = try uri_redirect.canonicalize(
                        allocator,
                        current_uri,
                    ),
                    .redirect_count = chain.redirects,
                };
            }
            const location = try uri_redirect.location(
                response.response.headers,
            );
            if (location == null) {
                return .{
                    .allocator = allocator,
                    .response = response,
                    .final_uri = try uri_redirect.canonicalize(
                        allocator,
                        current_uri,
                    ),
                    .redirect_count = chain.redirects,
                };
            }
            var next = try chain.follow(
                current_uri,
                location.?,
                response.response.status,
            );
            var next_owned = true;
            defer if (next_owned) next.deinit();

            const action = uri_redirect.methodAction(
                redirect_options.policy,
                response.response.status,
                hop_options.method,
            );
            const remove_credentials = next.cross_origin and
                !redirect_options.policy.forward_cross_origin_credentials;
            hop_options.headers = try redirectHeaders(
                allocator,
                hop_options.headers,
                remove_credentials,
                action == .rewrite_get,
                &owned_headers,
            );
            hop_options.host = null;
            if (action == .rewrite_get) {
                hop_options.method = .GET;
                hop_options.body = &.{};
                hop_options.trailers = &.{};
            } else if (remove_credentials) {
                // Trailer fields can carry the same credentials as head
                // fields, while rewriting an arbitrary Trailer value safely
                // would require owning and reparsing its name list. Drop the
                // complete trailer section and its declaration cross-origin.
                hop_options.trailers = &.{};
            }

            response.deinit(allocator);
            allocator.free(current_uri);
            current_uri = next.uri;
            next_owned = false;
        }
    }

    pub fn requestUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
    ) Error!OwnedResponse {
        return requestUriTls(allocator, io, uri_text, request_options, limits, .{});
    }

    pub fn requestUriTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!is_http and !is_https) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, if (is_https) 443 else 80);
        defer endpoint.deinit();

        const stream = switch (endpoint.target) {
            .host => |host| try tcp_connect.host(
                io,
                host,
                endpoint.port,
                limits.connect_timeout,
            ),
            .ip => |address| try tcp_connect.ip(
                io,
                address,
                limits.connect_timeout,
            ),
        };
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        var client = if (is_https) blk: {
            const tls_conn = try TlsClientConnection.init(allocator, io, stream, endpoint.tls_host, tls_options);
            stream_owned = false;
            errdefer tls_conn.deinit();
            const default_host = try allocator.dupe(u8, endpoint.authority);
            break :blk Client{
                .io = io,
                .allocator = allocator,
                .stream = stream,
                .limits = limits,
                .default_host = default_host,
                .tls_conn = tls_conn,
            };
        } else blk: {
            const default_host = try allocator.dupe(u8, endpoint.authority);
            stream_owned = false;
            break :blk Client{
                .io = io,
                .allocator = allocator,
                .stream = stream,
                .limits = limits,
                .default_host = default_host,
            };
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        return client.request(options);
    }

    pub fn requestUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return requestUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            .{},
            deadline,
        );
    }

    pub fn requestUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Perform a one-shot HTTP/HTTPS request under one absolute deadline. DNS,
    /// TCP, TLS, response heads, body, and trailers all consume the same
    /// budget; configured connect, TLS, and response-head limits may shorten
    /// their own phases but never extend the caller deadline.
    pub fn requestUriTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!is_http and !is_https) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(
            allocator,
            uri,
            if (is_https) 443 else 80,
        );
        defer endpoint.deinit();

        var client = if (is_https) switch (endpoint.target) {
            .host => try connectTlsHostWithDeadline(
                allocator,
                io,
                endpoint.tls_host,
                endpoint.port,
                limits,
                tls_options,
                deadline,
            ),
            .ip => |address| try connectTlsAddressWithDeadline(
                allocator,
                io,
                address,
                endpoint.tls_host,
                endpoint.authority,
                limits,
                tls_options,
                deadline,
            ),
        } else switch (endpoint.target) {
            .host => try connectHostWithDeadline(
                allocator,
                io,
                endpoint.tls_host,
                endpoint.port,
                limits,
                deadline,
            ),
            .ip => |address| blk: {
                var connected = try connectWithDeadline(
                    allocator,
                    io,
                    address,
                    limits,
                    deadline,
                );
                connected.default_host = try allocator.dupe(
                    u8,
                    endpoint.authority,
                );
                break :blk connected;
            },
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        return client.requestWithDeadline(options, deadline);
    }

    pub fn requestUriTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// One-shot HTTPS request through the vail TLS 1.3 client. Use this when
    /// the caller needs mTLS, ALPN, peer identity, exporter, or KeyUpdate; for
    /// persistent connections call `connectVailTlsHost` directly.
    pub fn requestUriVailTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, 443);
        defer endpoint.deinit();
        var client = switch (endpoint.target) {
            .host => try connectVailTlsHost(
                allocator,
                io,
                endpoint.tls_host,
                uri.port orelse 443,
                limits,
                tls_options,
            ),
            .ip => |address| try connectVailTlsAddress(
                allocator,
                io,
                address,
                endpoint.tls_host,
                limits,
                tls_options,
            ),
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        if (options.host == null) options.host = endpoint.authority;
        return client.request(options);
    }

    pub fn requestUriVailTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, 443);
        defer endpoint.deinit();
        var client = switch (endpoint.target) {
            .host => try connectVailTlsHostWithDeadline(
                allocator,
                io,
                endpoint.tls_host,
                uri.port orelse 443,
                limits,
                tls_options,
                deadline,
            ),
            .ip => |address| try connectVailTlsAddressWithDeadline(
                allocator,
                io,
                address,
                endpoint.tls_host,
                limits,
                tls_options,
                deadline,
            ),
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        if (options.host == null) options.host = endpoint.authority;
        return client.requestWithDeadline(options, deadline);
    }

    pub fn requestUriVailTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriVailTlsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn promoteConnectTunnelToTls(
        self: *Client,
        connect_target: []const u8,
        tls_host: []const u8,
        origin_authority: []const u8,
        proxy_headers: []const http1.Header,
        tls_options: TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.tls_conn != null or self.tls_vail_conn != null) {
            return error.InvalidResponse;
        }
        const owned_authority = try self.allocator.dupe(
            u8,
            origin_authority,
        );
        errdefer self.allocator.free(owned_authority);
        const tunnel = if (deadline) |absolute|
            try self.openConnectTunnelWithDeadline(
                connect_target,
                proxy_headers,
                absolute,
            )
        else
            try self.openConnectTunnel(connect_target, proxy_headers);
        if (tunnel.inbuf.items.len != 0 or tunnel.tls_conn != null or
            tunnel.tls_vail_conn != null or tunnel.tls_server_conn != null)
        {
            return error.InvalidResponse;
        }
        const tls_conn = if (deadline) |absolute|
            try TlsClientConnection.initWithDeadline(
                self.allocator,
                self.io,
                self.stream,
                tls_host,
                tls_options,
                absolute,
            )
        else
            try TlsClientConnection.init(
                self.allocator,
                self.io,
                self.stream,
                tls_host,
                tls_options,
            );
        if (self.default_host) |old| self.allocator.free(old);
        self.default_host = owned_authority;
        self.tls_conn = tls_conn;
        self.writer_state.phase = .idle;
    }

    pub fn openConnectTunnelWithTimeout(
        self: *Client,
        target: []const u8,
        headers: []const http1.Header,
        timeout: std.Io.Duration,
    ) Error!Tunnel {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openConnectTunnelWithDeadline(
            target,
            headers,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Open CONNECT under one absolute budget spanning request write,
    /// informational responses, and the final response entity.
    pub fn openConnectTunnelWithDeadline(
        self: *Client,
        target: []const u8,
        headers: []const http1.Header,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Tunnel {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.openConnectTunnel(target, headers);
    }

    pub fn openConnectTunnel(self: *Client, target: []const u8, headers: []const http1.Header) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try http1.validateConnectTarget(target);
        try self.writeRequestFailClosed(.{
            .method = .CONNECT,
            .target = target,
            .host = target,
            .headers = headers,
        });
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        var response = readResponseFromTransportBufferedForRequestObserved(
            self.allocator,
            self.transport(),
            self.limits,
            .{},
            &self.inbuf,
            .CONNECT,
            null,
            null,
            self.response_deadline,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        errdefer response.deinit(self.allocator);
        self.writer_state.phase = if (requestOptionsKeepAlive(.{ .method = .CONNECT, .target = target, .headers = headers }) and responseIsReusable(response.response, .CONNECT)) .idle else .unusable;
        // Even a response rejected by the CONNECT adapter may have switched
        // the peer's framing (101 or successful CONNECT). Never resume HTTP
        // on that socket; retain TLS ownership while waking the peer.
        errdefer if (message_reuse.switchesProtocol(.CONNECT, response.response.status)) self.transport().abort();
        if (response.response.status < 200 or response.response.status >= 300) return error.InvalidResponse;
        if (response.response.body.len != 0 or response.response.trailers.len != 0) return error.InvalidResponse;
        response.deinit(self.allocator);
        // A successful CONNECT transfers exclusive ownership of the byte
        // stream to Tunnel. The HTTP client must never issue another request
        // or let a pool return this socket to its idle set.
        self.writer_state.phase = .unusable;
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .tls_conn = self.tls_conn,
            .tls_vail_conn = self.tls_vail_conn,
            .inbuf = &self.inbuf,
        };
    }

    /// Open RFC 9298 CONNECT-UDP over the HTTP/1.1 Upgrade mapping. The
    /// request target is the expanded absolute URI, matching the RFC's proxy
    /// form, and no Capsule bytes are sent until the validated 101 response.
    pub fn openConnectUdp(
        self: *Client,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        uri_storage: []u8,
    ) Error!ConnectUdpSession {
        return self.openConnectUdpUntil(
            template,
            target,
            variables,
            uri_storage,
            null,
        );
    }

    pub fn openConnectUdpWithTimeout(
        self: *Client,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        uri_storage: []u8,
        timeout: std.Io.Duration,
    ) Error!ConnectUdpSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openConnectUdpWithDeadline(
            template,
            target,
            variables,
            uri_storage,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn openConnectUdpWithDeadline(
        self: *Client,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        uri_storage: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectUdpSession {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.openConnectUdpUntil(
            template,
            target,
            variables,
            uri_storage,
            deadline,
        );
    }

    fn openConnectUdpUntil(
        self: *Client,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        uri_storage: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectUdpSession {
        try target.validate();
        const expected_scheme: []const u8 = if (self.tls_conn != null or
            self.tls_vail_conn != null) "https" else "http";
        if (!std.ascii.eqlIgnoreCase(template.scheme, expected_scheme)) {
            return error.InvalidUriTemplate;
        }
        const request_target = try template.expandUriInto(
            uri_storage,
            target.host,
            target.port,
            variables,
        );
        const headers = [_]http1.Header{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        if (deadline) |absolute| {
            std.debug.assert(self.response_deadline == null);
            self.response_deadline = absolute;
        }
        defer if (deadline != null) {
            self.response_deadline = null;
        };
        try self.writeUpgradeRequest(
            request_target,
            template.authority,
            http3.connect_udp.protocol,
            &headers,
        );
        const tunnel = try self.finishUpgradeInternal(
            http3.connect_udp.protocol,
            true,
        );
        return ConnectUdpSession.init(
            self.allocator,
            self.io,
            ConnectUdpTunnel.init(self.allocator, tunnel),
            .{},
        );
    }

    /// Open RFC 9484 CONNECT-IP over an encrypted HTTP/1.1 Upgrade.
    pub fn openConnectIp(
        self: *Client,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        uri_storage: []u8,
    ) Error!ConnectIpSession {
        return self.openConnectIpUntil(
            template,
            scope,
            variables,
            uri_storage,
            null,
        );
    }

    pub fn openConnectIpWithTimeout(
        self: *Client,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        uri_storage: []u8,
        timeout: std.Io.Duration,
    ) Error!ConnectIpSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openConnectIpWithDeadline(
            template,
            scope,
            variables,
            uri_storage,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn openConnectIpWithDeadline(
        self: *Client,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        uri_storage: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectIpSession {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.openConnectIpUntil(
            template,
            scope,
            variables,
            uri_storage,
            deadline,
        );
    }

    fn openConnectIpUntil(
        self: *Client,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        uri_storage: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectIpSession {
        if (self.tls_conn == null and self.tls_vail_conn == null) {
            return error.EncryptionRequired;
        }
        try scope.validate();
        if (!std.ascii.eqlIgnoreCase(template.scheme(), "https")) {
            return error.InvalidUriTemplate;
        }
        const request_target = try template.expandUriInto(
            uri_storage,
            scope,
            variables,
        );
        const headers = [_]http1.Header{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        if (deadline) |absolute| {
            std.debug.assert(self.response_deadline == null);
            self.response_deadline = absolute;
        }
        defer if (deadline != null) {
            self.response_deadline = null;
        };
        try self.writeUpgradeRequest(
            request_target,
            template.authority(),
            http3.connect_ip.protocol,
            &headers,
        );
        const tunnel = try self.finishUpgradeInternal(
            http3.connect_ip.protocol,
            true,
        );
        return ConnectIpSession.init(
            self.allocator,
            self.io,
            ConnectUdpTunnel.init(self.allocator, tunnel),
            .{},
        );
    }

    /// Relative-timeout wrapper for the complete Upgrade handshake.
    pub fn openUpgradeWithTimeout(
        self: *Client,
        target: []const u8,
        host: ?[]const u8,
        protocol: []const u8,
        headers: []const http1.Header,
        timeout: std.Io.Duration,
    ) Error!Tunnel {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openUpgradeWithDeadline(
            target,
            host,
            protocol,
            headers,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Perform the request write and complete Upgrade under one deadline.
    pub fn openUpgradeWithDeadline(
        self: *Client,
        target: []const u8,
        host: ?[]const u8,
        protocol: []const u8,
        headers: []const http1.Header,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Tunnel {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.openUpgrade(target, host, protocol, headers);
    }

    /// Perform a generic HTTP/1.1 Upgrade and transfer the underlying byte
    /// stream to the caller after validating the peer's 101 response. Bytes
    /// already read beyond the response head remain available through
    /// `Tunnel.read`, which is essential when the upgraded peer sends its
    /// protocol preface immediately with the 101.
    pub fn openUpgrade(
        self: *Client,
        target: []const u8,
        host: ?[]const u8,
        protocol: []const u8,
        headers: []const http1.Header,
    ) Error!Tunnel {
        try self.writeUpgradeRequest(target, host, protocol, headers);
        return self.finishUpgrade(protocol);
    }

    fn writeUpgradeRequest(
        self: *Client,
        target: []const u8,
        host: ?[]const u8,
        protocol: []const u8,
        headers: []const http1.Header,
    ) Error!void {
        try self.writer_state.ensureAvailable();
        try validateUpgradeProtocol(protocol);
        try rejectUpgradeManagedHeaders(headers);
        var upgrade_headers: std.ArrayList(http1.Header) = .empty;
        defer upgrade_headers.deinit(self.allocator);
        try upgrade_headers.ensureTotalCapacity(
            self.allocator,
            headers.len + 2,
        );
        upgrade_headers.appendAssumeCapacity(.{
            .name = "Connection",
            .value = "Upgrade",
        });
        upgrade_headers.appendAssumeCapacity(.{
            .name = "Upgrade",
            .value = protocol,
        });
        upgrade_headers.appendSliceAssumeCapacity(headers);
        try self.writeRequestFailClosed(.{
            .method = .GET,
            .target = target,
            .host = host orelse self.default_host,
            .headers = upgrade_headers.items,
        });
    }

    /// Relative-timeout wrapper for an already-written Upgrade request.
    pub fn finishUpgradeWithTimeout(
        self: *Client,
        protocol: []const u8,
        timeout: std.Io.Duration,
    ) Error!Tunnel {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishUpgradeWithDeadline(
            protocol,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn finishUpgradeWithDeadline(
        self: *Client,
        protocol: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Tunnel {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.finishUpgrade(protocol);
    }

    /// Complete a generic Upgrade from an already-written request. This split
    /// form supports callers that must coalesce their first protocol bytes
    /// with the HTTP request while preserving any response suffix read ahead.
    pub fn finishUpgrade(
        self: *Client,
        protocol: []const u8,
    ) Error!Tunnel {
        return self.finishUpgradeInternal(protocol, false);
    }

    fn finishUpgradeInternal(
        self: *Client,
        protocol: []const u8,
        require_capsule_protocol: bool,
    ) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try validateUpgradeProtocol(protocol);
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        var response = readResponseFromTransportBufferedForRequestObserved(
            self.allocator,
            self.transport(),
            self.limits,
            .{},
            &self.inbuf,
            .GET,
            null,
            null,
            self.response_deadline,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        errdefer response.deinit(self.allocator);
        self.writer_state.phase = if (!require_capsule_protocol and responseIsReusable(response.response, .GET)) .idle else .unusable;
        // The peer exits HTTP at 101, before application-specific protocol
        // validation. A failed handoff must abort instead of reusing HTTP.
        errdefer if (require_capsule_protocol or message_reuse.switchesProtocol(.GET, response.response.status)) self.transport().abort();
        if (response.response.version != .http_1_1) return error.InvalidResponse;
        const selected = response.response.upgradeProtocol() orelse return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(selected, protocol) or
            response.response.body.len != 0 or
            response.response.trailers.len != 0)
        {
            return error.InvalidResponse;
        }
        if (require_capsule_protocol) {
            const enabled = http3.capsule.protocolEnabled(
                response.response.headers,
            ) catch {
                return error.InvalidResponse;
            };
            if (!enabled) {
                return error.InvalidResponse;
            }
        }
        response.deinit(self.allocator);
        self.writer_state.phase = .unusable;
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .tls_conn = self.tls_conn,
            .tls_vail_conn = self.tls_vail_conn,
            .inbuf = &self.inbuf,
        };
    }

    pub fn readStreamingResponse(
        self: *Client,
        request_method: http1.Method,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        informational_responses_seen: ?*usize,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        var reader = StreamingBodyReader{
            .allocator = self.allocator,
            .context = self,
            .read_some = clientReadSome,
            .read_head_some = clientReadHeadSome,
            .inbuf = &self.inbuf,
            .limits = .{
                .max_head_bytes = self.limits.max_head_bytes,
                .max_body_bytes = self.limits.max_body_bytes,
                .max_informational_responses = self.limits.max_informational_responses,
            },
            .options = parse_options,
            .informational_context = if (informational) |observer|
                observer.context
            else
                null,
            .on_informational = if (informational) |observer|
                observer.on_response
            else
                null,
            .informational_responses_seen = informational_responses_seen,
        };
        const result = reader.readResponse(
            request_method,
            context,
            begin,
            consume,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        return streamingResponseFromReader(result);
    }

    pub fn beginResponseHeadSequence(self: *Client) void {
        std.debug.assert(!self.response_head_sequence_active);
        std.debug.assert(self.response_head_deadline == null);
        self.response_head_sequence_active = true;
    }

    pub fn ensureResponseHeadDeadline(
        self: *Client,
    ) Error!?std.Io.Clock.Timestamp {
        try ensureResponseHeadDeadlineForBuffer(
            self.transport(),
            self.limits,
            self.inbuf.items,
            &self.response_head_deadline,
        );
        return self.response_head_deadline;
    }

    pub fn endResponseHeadSequence(self: *Client) void {
        self.response_head_deadline = null;
        self.response_head_sequence_active = false;
    }
};

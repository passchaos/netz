//! WebSocket client connection establishment and handshake.

const std = @import("std");
const websocket = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const endpoint_host = @import("../../internal/endpoint_host.zig");
const tls_policy = @import("client/tls_policy.zig");

const ConnectAttempt = runtime.ConnectAttempt;
const ConnectOptions = runtime.ConnectOptions;
const Connection = runtime.Connection;
const Error = runtime.Error;
const HandshakeWriter = runtime.HandshakeWriter;
const HttpProxyOptions = runtime.HttpProxyOptions;
const Limits = runtime.Limits;
const RedirectConnectAttempt = runtime.RedirectConnectAttempt;
const RedirectOptions = runtime.RedirectOptions;
const RuntimeTransport = runtime.RuntimeTransport;
const Socks5RedirectProxy = runtime.Socks5RedirectProxy;
const address_resolver = runtime.address_resolver;
const clearRedirectTlsTickets = runtime.clearRedirectTlsTickets;
const connectNamedEndpointBefore = runtime.connectNamedEndpointBefore;
const connectUriEndpointBefore = runtime.connectUriEndpointBefore;
const deadline_policy = runtime.deadline_policy;
const handshakeDeadline = runtime.handshakeDeadline;
const handshake_headers = runtime.handshake_headers;
const handshake_request = runtime.handshake_request;
const handshake_storage = runtime.handshake_storage;
const hasClientIdentity = runtime.hasClientIdentity;
const http1 = runtime.http1;
const http1HandshakeResponseParseOptions = runtime.http1HandshakeResponseParseOptions;
const http1_message_framing = runtime.http1_message_framing;
const http1_runtime = runtime.http1_runtime;
const proxy_socks5 = runtime.proxy_socks5;
const readHttpHeadFromTransport = runtime.readHttpHeadFromTransport;
const readHttpHeadFromTransportWithInitial = runtime.readHttpHeadFromTransportWithInitial;
const readHttpUpgradeResponseBytes = runtime.readHttpUpgradeResponseBytes;
const redirect = runtime.redirect;
const socket_options = runtime.socket_options;
const tcp_connect = runtime.tcp_connect;
const tls_client_identity = runtime.tls_client_identity;
const uriTargetAlloc = runtime.uriTargetAlloc;
const validateHttp1ClientExtraHeadersImpl = runtime.validateHttp1ClientExtraHeadersImpl;

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
        var attempt = try connectAcceptedStreamAttempt(
            allocator,
            io,
            stream,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAcceptedStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var attempt = try connectStreamAttempt(
            allocator,
            io,
            stream,
            null,
            options,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
    }

    /// Apply one caller-owned deadline to the opening handshake on an already
    /// connected cleartext tunnel. Ownership transfers at entry.
    pub fn connectAcceptedStreamWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectAcceptedStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAcceptedStreamAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        _ = try deadline_policy.usableAwake(io, deadline);
        var attempt = try connectStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            null,
            options,
            deadline,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectAcceptedStreamWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) {
            stream.close(io);
            return error.Timeout;
        }
        return connectAcceptedStreamWithDeadline(
            allocator,
            io,
            stream,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAcceptedStreamAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) {
            stream.close(io);
            return error.Timeout;
        }
        return connectAcceptedStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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
        var attempt = try connectAcceptedTlsStreamAttempt(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAcceptedTlsStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        return connectAcceptedTlsStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
            null,
        );
    }

    pub fn connectAcceptedTlsStreamWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectAcceptedTlsStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAcceptedTlsStreamAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        return connectAcceptedTlsStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
            deadline,
        );
    }

    pub fn connectAcceptedTlsStreamWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) {
            stream.close(io);
            return error.Timeout;
        }
        return connectAcceptedTlsStreamWithDeadline(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAcceptedTlsStreamAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) {
            stream.close(io);
            return error.Timeout;
        }
        return connectAcceptedTlsStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectAcceptedTlsStreamAttemptMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(io, absolute);
        }
        const effective_tls_options = tls_policy.effective(options, tls_options);
        if (options.vail_tls orelse options.tls_identity) |identity| {
            const tls_conn = if (deadline) |absolute|
                try tls_client_identity.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    server_name,
                    effective_tls_options,
                    identity,
                    absolute,
                )
            else
                try tls_client_identity.init(
                    allocator,
                    io,
                    stream,
                    server_name,
                    effective_tls_options,
                    identity,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            var attempt = try connectTransportAttempt(
                allocator,
                io,
                .{ .tls_vail = tls_conn },
                options,
                deadline,
            );
            return closeRejectedAttempt(&attempt);
        }
        const tls_conn = if (deadline) |absolute|
            try http1_runtime.TlsClientConnection.initWithDeadline(
                allocator,
                io,
                stream,
                server_name,
                effective_tls_options,
                absolute,
            )
        else
            try http1_runtime.TlsClientConnection.init(
                allocator,
                io,
                stream,
                server_name,
                effective_tls_options,
            );
        stream_owned = false;
        errdefer tls_conn.deinit();
        var attempt = try connectTransportAttempt(
            allocator,
            io,
            .{ .tls = tls_conn },
            options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!Connection {
        var attempt = try connectAttempt(allocator, io, address, options);
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try tcp_connect.ipWithOptions(io, address, options.connect_timeout, options);
        errdefer stream.close(io);
        var attempt = try connectStreamAttempt(allocator, io, stream, null, options);
        return closeRejectedAttempt(&attempt);
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
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try tcp_connect.ipWithDeadlineAndOptions(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
            options,
        );
        errdefer stream.close(io);
        var attempt = try connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            null,
            options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
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

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
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
        var attempt = try connectUnixAttempt(allocator, io, address, options);
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUnixAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        if (options.tcp_keepalive != null or
            options.tcp_user_timeout_ms != null)
        {
            return error.SocketOptionUnsupported;
        }
        if (options.host.len == 0) return error.InvalidUri;
        try tcp_connect.validateUnixOptions(options);
        const stream = try tcp_connect.unix(io, address, options.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connect_options = options;
        connect_options.tcp_nodelay = false;
        var attempt = try connectStreamAttempt(
            allocator,
            io,
            stream,
            null,
            connect_options,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectUnixAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUnixAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        if (options.tcp_keepalive != null or
            options.tcp_user_timeout_ms != null)
        {
            return error.SocketOptionUnsupported;
        }
        if (options.host.len == 0) return error.InvalidUri;
        try tcp_connect.validateUnixOptions(options);
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
        var attempt = try connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            null,
            connect_options,
            deadline,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
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

    pub fn connectUnixAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixAttemptWithDeadline(
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
        var attempt = try connectHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try connectNamedEndpointBefore(
            allocator,
            io,
            host,
            port,
            options,
            null,
        );
        errdefer stream.close(io);
        const parsed = try endpoint_host.parse(host, port);
        const default_host = if (options.host.len == 0) try parsed.authorityAlloc(allocator, port) else null;
        defer if (default_host) |authority| allocator.free(authority);
        var connect_options = options;
        if (default_host) |authority| connect_options.host = authority;
        var attempt = try connectStreamAttempt(
            allocator,
            io,
            stream,
            null,
            connect_options,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try connectNamedEndpointBefore(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        errdefer stream.close(io);
        const parsed = try endpoint_host.parse(host, port);
        const default_host = if (options.host.len == 0) try parsed.authorityAlloc(allocator, port) else null;
        defer if (default_host) |authority| allocator.free(authority);
        var connect_options = options;
        if (default_host) |authority| connect_options.host = authority;
        var attempt = try connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            null,
            connect_options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
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

    pub fn connectHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
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

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var attempt = try connectTlsHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        const stream = try connectNamedEndpointBefore(
            allocator,
            io,
            host,
            port,
            options,
            null,
        );
        var attempt = try connectTlsStreamAttempt(
            allocator,
            io,
            stream,
            host,
            port,
            options,
            tls_options,
        );
        return closeRejectedAttempt(&attempt);
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
        var attempt = try connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const stream = try connectNamedEndpointBefore(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        var attempt = try connectTlsStreamAttemptBefore(
            allocator,
            io,
            stream,
            host,
            port,
            options,
            tls_options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
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

    pub fn connectTlsHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostAttemptWithDeadline(
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
        var attempt = try connectTlsAddressAttempt(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsAddressAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        _ = try endpoint_host.parse(tls_host, address.getPort());
        const stream = try tcp_connect.ipWithOptions(
            io,
            address,
            options.connect_timeout,
            options,
        );
        var attempt = try connectTlsStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            options,
            tls_options,
        );
        return closeRejectedAttempt(&attempt);
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
        var attempt = try connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsAddressAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try endpoint_host.parse(tls_host, address.getPort());
        const stream = try tcp_connect.ipWithDeadlineAndOptions(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
            options,
        );
        var attempt = try connectTlsStreamAttemptBefore(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            options,
            tls_options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
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

    pub fn connectTlsAddressAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectTlsStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        return connectTlsStreamAttemptMaybeBefore(
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

    fn connectTlsStreamAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectTlsStreamAttemptMaybeBefore(
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

    fn connectTlsStreamAttemptMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const parsed = try endpoint_host.parse(tls_host, port);
        try socket_options.applyTcp(stream, .{
            .no_delay = options.tcp_nodelay,
            .keep_alive = options.tcp_keepalive,
            .user_timeout_ms = options.tcp_user_timeout_ms,
        });
        const default_host = if (options.host.len == 0) try parsed.authorityAlloc(allocator, port) else null;
        defer if (default_host) |authority| allocator.free(authority);
        var connect_options = options;
        if (default_host) |authority| connect_options.host = authority;
        const effective_tls_options = tls_policy.effective(options, tls_options);
        if (connect_options.vail_tls orelse
            connect_options.tls_identity) |identity|
        {
            const tls_conn = if (deadline) |absolute|
                try tls_client_identity.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    parsed.host,
                    effective_tls_options,
                    identity,
                    absolute,
                )
            else
                try tls_client_identity.init(
                    allocator,
                    io,
                    stream,
                    parsed.host,
                    effective_tls_options,
                    identity,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return connectTransportAttempt(
                allocator,
                io,
                .{ .tls_vail = tls_conn },
                connect_options,
                deadline,
            );
        }
        const tls_conn = if (deadline) |absolute|
            try http1_runtime.TlsClientConnection.initWithDeadline(
                allocator,
                io,
                stream,
                parsed.host,
                effective_tls_options,
                absolute,
            )
        else
            try http1_runtime.TlsClientConnection.init(
                allocator,
                io,
                stream,
                parsed.host,
                effective_tls_options,
            );
        stream_owned = false;
        errdefer tls_conn.deinit();
        return connectTransportAttempt(
            allocator,
            io,
            .{ .tls = tls_conn },
            connect_options,
            deadline,
        );
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!Connection {
        return connectUriTls(allocator, io, uri_text, options, .{});
    }

    /// Establish WS/WSS through a cleartext HTTP proxy. Both schemes use
    /// CONNECT so the WebSocket opening handshake remains end-to-end; WSS then
    /// authenticates TLS on the tunneled stream. Proxy-only headers are never
    /// included in the Upgrade request.
    pub fn connectUriViaProxy(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var attempt = try connectUriViaProxyAttemptBefore(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            tls_options,
            null,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriViaProxyAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        var attempt = try connectUriViaProxyAttemptBefore(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            tls_options,
            null,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUriViaProxyWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectUriViaProxyAttemptBefore(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriViaProxyAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var attempt = try connectUriViaProxyAttemptBefore(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUriViaProxyWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaProxyWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriViaProxyAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaProxyAttemptWithDeadline(
            allocator,
            io,
            proxy_uri,
            uri_text,
            options,
            proxy_options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Establish WS/WSS through a SOCKS5 CONNECT tunnel. Destination DNS stays
    /// at the proxy, while Host, SNI, and certificate verification remain bound
    /// to the origin URI.
    pub fn connectUriViaSocks5(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var attempt = try connectUriViaSocks5AttemptBefore(
            allocator,
            io,
            proxy,
            uri_text,
            options,
            tls_options,
            null,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriViaSocks5Attempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        return connectUriViaSocks5AttemptBefore(
            allocator,
            io,
            proxy,
            uri_text,
            options,
            tls_options,
            null,
        );
    }

    pub fn connectUriViaSocks5WithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectUriViaSocks5AttemptBefore(
            allocator,
            io,
            proxy,
            uri_text,
            options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriViaSocks5AttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        return connectUriViaSocks5AttemptBefore(
            allocator,
            io,
            proxy,
            uri_text,
            options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn connectUriViaSocks5WithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaSocks5WithDeadline(
            allocator,
            io,
            proxy,
            uri_text,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriViaSocks5AttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriViaSocks5AttemptWithDeadline(
            allocator,
            io,
            proxy,
            uri_text,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Follow bounded HTTP Upgrade redirects until one WebSocket is accepted.
    /// Relative Location values use RFC 3986 resolution. By default WSS cannot
    /// downgrade to WS, cross-origin custom fields are stripped, and a client
    /// certificate cannot cross origins. `redirect_options.proxy`, when set,
    /// opens a fresh CONNECT tunnel for every hop.
    pub fn connectUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
    ) Error!Connection {
        var result = try connectUriFollowingRedirectsDetailedAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            null,
        );
        errdefer result.deinit();
        return result.requireAccepted();
    }

    /// Preserve the final accepted or non-redirect rejection response after
    /// consuming and closing every intermediate redirect response.
    pub fn connectUriFollowingRedirectsAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
    ) Error!ConnectAttempt {
        var result = try connectUriFollowingRedirectsDetailedAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            null,
        );
        return result.takeAttempt();
    }

    pub fn connectUriFollowingRedirectsDetailedAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
    ) Error!RedirectConnectAttempt {
        return connectUriFollowingRedirectsDetailedAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            null,
        );
    }

    /// Retain one absolute caller budget across all DNS/TCP, proxy CONNECT,
    /// origin TLS, rejection draining, and Upgrade work in the redirect chain.
    pub fn connectUriFollowingRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var result = try connectUriFollowingRedirectsDetailedAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        errdefer result.deinit();
        return result.requireAccepted();
    }

    pub fn connectUriFollowingRedirectsAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var result = try connectUriFollowingRedirectsDetailedAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return result.takeAttempt();
    }

    pub fn connectUriFollowingRedirectsDetailedAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!RedirectConnectAttempt {
        return connectUriFollowingRedirectsDetailedAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn connectUriFollowingRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingRedirectsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriFollowingRedirectsAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingRedirectsAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriFollowingRedirectsDetailedAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) Error!RedirectConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriFollowingRedirectsDetailedAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriFollowingRedirectsDetailedAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        redirect_options: RedirectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!RedirectConnectAttempt {
        if (redirect_options.proxy != null and
            redirect_options.socks5_proxy != null)
        {
            return error.InvalidRedirect;
        }
        var chain = redirect.Chain.init(
            allocator,
            redirect_options.policy,
        );
        defer chain.deinit();
        try chain.recordInitial(uri_text);
        var current_uri = try allocator.dupe(u8, uri_text);
        var current_uri_owned = true;
        defer if (current_uri_owned) allocator.free(current_uri);
        var hop_options = options;
        var crossed_origin = false;
        if (redirect_options.cookies != null) {
            for (options.extra_headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "cookie") or
                    std.ascii.eqlIgnoreCase(header.name, "cookie2"))
                {
                    return error.CookieHeaderConflict;
                }
            }
        }

        while (true) {
            var effective_options = hop_options;
            var cookie_value: ?[]u8 = null;
            defer if (cookie_value) |value| allocator.free(value);
            var cookie_headers: ?[]http1.Header = null;
            defer if (cookie_headers) |headers| allocator.free(headers);
            if (redirect_options.cookies) |cookie_options| {
                var request_context = cookie_options.request_context;
                request_context.method = "GET";
                request_context.http_api = true;
                if (crossed_origin and
                    cookie_options.cross_origin_is_cross_site)
                {
                    request_context.site = .cross_site;
                }
                const value = try cookie_options.jar.cookieHeaderValueAlloc(
                    allocator,
                    current_uri,
                    std.Io.Clock.real.now(io).toSeconds(),
                    request_context,
                );
                cookie_value = value;
                if (value.len != 0) {
                    const headers = try allocator.alloc(
                        http1.Header,
                        hop_options.extra_headers.len + 1,
                    );
                    @memcpy(
                        headers[0..hop_options.extra_headers.len],
                        hop_options.extra_headers,
                    );
                    headers[hop_options.extra_headers.len] = .{
                        .name = "cookie",
                        .value = value,
                    };
                    cookie_headers = headers;
                    effective_options.extra_headers = headers;
                }
            }
            var attempt = if (redirect_options.proxy) |proxy|
                if (deadline) |absolute|
                    try connectUriViaProxyAttemptWithDeadline(
                        allocator,
                        io,
                        proxy.uri,
                        current_uri,
                        effective_options,
                        proxy.options,
                        redirect_options.tls,
                        absolute,
                    )
                else
                    try connectUriViaProxyAttempt(
                        allocator,
                        io,
                        proxy.uri,
                        current_uri,
                        effective_options,
                        proxy.options,
                        redirect_options.tls,
                    )
            else if (redirect_options.socks5_proxy) |socks_proxy|
                if (deadline) |absolute|
                    try connectUriViaSocks5AttemptWithDeadline(
                        allocator,
                        io,
                        socks_proxy,
                        current_uri,
                        effective_options,
                        redirect_options.tls,
                        absolute,
                    )
                else
                    try connectUriViaSocks5Attempt(
                        allocator,
                        io,
                        socks_proxy,
                        current_uri,
                        effective_options,
                        redirect_options.tls,
                    )
            else if (deadline) |absolute|
                try connectUriTlsAttemptWithDeadline(
                    allocator,
                    io,
                    current_uri,
                    effective_options,
                    redirect_options.tls,
                    absolute,
                )
            else
                try connectUriTlsAttempt(
                    allocator,
                    io,
                    current_uri,
                    effective_options,
                    redirect_options.tls,
                );
            errdefer attempt.deinit();
            if (redirect_options.cookies) |cookie_options| {
                var store_context = cookie_options.store_context;
                store_context.http_api = true;
                if (crossed_origin and
                    cookie_options.cross_origin_is_cross_site)
                {
                    store_context.site = .cross_site;
                }
                for (attempt.headers()) |header| {
                    if (!std.ascii.eqlIgnoreCase(
                        header.name,
                        "set-cookie",
                    )) continue;
                    _ = try cookie_options.jar.storeSetCookieWithContext(
                        current_uri,
                        header.value,
                        std.Io.Clock.real.now(io).toSeconds(),
                        store_context,
                    );
                }
            }
            if (attempt.accepted() or
                !redirect.isRedirectStatus(attempt.status()))
            {
                current_uri_owned = false;
                return .{
                    .allocator = allocator,
                    .attempt = attempt,
                    .final_uri = current_uri,
                    .redirect_count = chain.redirects,
                };
            }
            const location = try redirect.location(attempt.headers());
            if (location == null) {
                current_uri_owned = false;
                return .{
                    .allocator = allocator,
                    .attempt = attempt,
                    .final_uri = current_uri,
                    .redirect_count = chain.redirects,
                };
            }
            var next = try chain.follow(
                current_uri,
                location.?,
                attempt.status(),
            );
            var next_owned = true;
            defer if (next_owned) next.deinit();
            if (next.cross_origin) {
                try redirect.enforceClientIdentityPolicy(
                    redirect_options.policy,
                    true,
                    hasClientIdentity(hop_options),
                );
                hop_options.host = "";
                if (!redirect_options.policy.forward_cross_origin_headers) {
                    hop_options.extra_headers = &.{};
                }
                clearRedirectTlsTickets(&hop_options);
                crossed_origin = true;
            }
            if (!next.secure) {
                // An explicitly permitted downgrade cannot carry TLS-only
                // configuration into the cleartext URI helper.
                hop_options.tls_identity = null;
                hop_options.vail_tls = null;
            }
            attempt.deinit();
            allocator.free(current_uri);
            current_uri = next.uri;
            next_owned = false;
        }
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

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        return connectUriTlsAttempt(allocator, io, uri_text, options, .{});
    }

    pub fn connectUriTlsAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        var attempt = try connectUriTlsAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            null,
        );
        return closeRejectedAttempt(&attempt);
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

    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        return connectUriTlsAttemptWithDeadline(
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

    pub fn connectUriAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAttemptWithDeadline(
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

    pub fn connectUriTlsAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var attempt = try connectUriTlsAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return closeRejectedAttempt(&attempt);
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

    pub fn connectUriTlsAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriTlsAttemptWithDeadline(
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
        var attempt = try connectUriTlsAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    fn connectUriTlsAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
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

        const stream = try connectUriEndpointBefore(
            allocator,
            io,
            endpoint,
            options,
            deadline,
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        try socket_options.applyTcp(stream, .{
            .no_delay = options.tcp_nodelay,
            .keep_alive = options.tcp_keepalive,
            .user_timeout_ms = options.tcp_user_timeout_ms,
        });
        if (is_wss) {
            const effective_tls_options = tls_policy.effective(options, tls_options);
            if (options.vail_tls orelse options.tls_identity) |identity| {
                const tls_conn = if (deadline) |absolute|
                    try tls_client_identity.initWithDeadline(
                        allocator,
                        io,
                        stream,
                        endpoint.tls_host,
                        effective_tls_options,
                        identity,
                        absolute,
                    )
                else
                    try tls_client_identity.init(
                        allocator,
                        io,
                        stream,
                        endpoint.tls_host,
                        effective_tls_options,
                        identity,
                    );
                stream_owned = false;
                errdefer tls_conn.deinit();
                return connectTransportAttempt(
                    allocator,
                    io,
                    .{ .tls_vail = tls_conn },
                    connect_options,
                    deadline,
                );
            }
            const tls_conn = if (deadline) |absolute|
                try http1_runtime.TlsClientConnection.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    effective_tls_options,
                    absolute,
                )
            else
                try http1_runtime.TlsClientConnection.init(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    effective_tls_options,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return connectTransportAttempt(
                allocator,
                io,
                .{ .tls = tls_conn },
                connect_options,
                deadline,
            );
        }
        const attempt = try connectTransportAttempt(
            allocator,
            io,
            .{ .tcp = .{ .io = io, .stream = stream } },
            connect_options,
            deadline,
        );
        stream_owned = false;
        return attempt;
    }

    fn connectUriViaSocks5AttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Socks5RedirectProxy,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_ws = std.ascii.eqlIgnoreCase(uri.scheme, "ws");
        const is_wss = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!is_ws and !is_wss) return error.UnsupportedScheme;
        if ((options.tls_identity != null or options.vail_tls != null) and
            !is_wss)
        {
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(
            allocator,
            uri,
            if (is_wss) 443 else 80,
        );
        defer endpoint.deinit();
        var effective_proxy_options = proxy.options;
        if (options.local_address) |address| effective_proxy_options.local_address = address;
        if (options.network_interface) |interface| effective_proxy_options.network_interface = interface;
        if (effective_proxy_options.connect_timeout == null) {
            effective_proxy_options.connect_timeout = options.connect_timeout;
        }
        if (effective_proxy_options.address_resolver == null) {
            effective_proxy_options.address_resolver = options.address_resolver;
        }
        if (effective_proxy_options.address_connect_policy == null) {
            effective_proxy_options.address_connect_policy =
                options.address_connect_policy;
        }
        const stream = if (deadline) |absolute|
            try proxy_socks5.connectHostWithDeadline(
                allocator,
                io,
                proxy.host,
                proxy.port,
                endpoint.tls_host,
                endpoint.port,
                effective_proxy_options,
                absolute,
            )
        else
            try proxy_socks5.connectHost(
                allocator,
                io,
                proxy.host,
                proxy.port,
                endpoint.tls_host,
                endpoint.port,
                effective_proxy_options,
            );
        var connect_options = options;
        connect_options.target = target;
        if (connect_options.host.len == 0) {
            connect_options.host = endpoint.authority;
        }
        if (is_wss) {
            return if (deadline) |absolute|
                connectAcceptedTlsStreamAttemptWithDeadline(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    connect_options,
                    tls_options,
                    absolute,
                )
            else
                connectAcceptedTlsStreamAttempt(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    connect_options,
                    tls_options,
                );
        }
        return if (deadline) |absolute|
            connectAcceptedStreamAttemptWithDeadline(
                allocator,
                io,
                stream,
                connect_options,
                absolute,
            )
        else
            connectAcceptedStreamAttempt(
                allocator,
                io,
                stream,
                connect_options,
            );
    }

    fn connectUriViaProxyAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_uri: []const u8,
        uri_text: []const u8,
        options: ConnectOptions,
        proxy_options: HttpProxyOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_ws = std.ascii.eqlIgnoreCase(uri.scheme, "ws");
        const is_wss = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!is_ws and !is_wss) return error.UnsupportedScheme;
        if ((options.tls_identity != null or options.vail_tls != null) and
            !is_wss)
        {
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(
            allocator,
            uri,
            if (is_wss) 443 else 80,
        );
        defer endpoint.deinit();
        const connect_target = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ endpoint.host_storage, endpoint.port },
        );
        defer allocator.free(connect_target);
        const http_limits = http1_runtime.Limits{
            .max_head_bytes = options.limits.max_head_bytes,
            .max_body_bytes = options.limits.max_rejection_body_bytes,
            .response_head_timeout = options.limits.http1_handshake_timeout,
            .max_informational_responses = options.limits.max_informational_responses,
            .connect_timeout = options.connect_timeout,
            .local_address = options.local_address,
            .network_interface = options.network_interface,
            .tcp_nodelay = options.tcp_nodelay,
        };
        var effective_proxy_options = proxy_options;
        if (effective_proxy_options.address_resolver == null) {
            effective_proxy_options.address_resolver = options.address_resolver;
        }
        if (effective_proxy_options.address_connect_policy == null) {
            effective_proxy_options.address_connect_policy =
                options.address_connect_policy;
        }
        const stream = if (deadline) |absolute|
            try http1_runtime.Client.connectTunnelViaProxyUriWithDeadline(
                allocator,
                io,
                proxy_uri,
                connect_target,
                effective_proxy_options,
                http_limits,
                absolute,
            )
        else
            try http1_runtime.Client.connectTunnelViaProxyUri(
                allocator,
                io,
                proxy_uri,
                connect_target,
                effective_proxy_options,
                http_limits,
            );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connect_options = options;
        connect_options.target = target;
        if (connect_options.host.len == 0) {
            connect_options.host = endpoint.authority;
        }
        if (is_wss) {
            stream_owned = false;
            return connectTlsStreamAttemptMaybeBefore(
                allocator,
                io,
                stream,
                endpoint.tls_host,
                endpoint.port,
                connect_options,
                tls_options,
                deadline,
            );
        }
        const attempt = if (deadline) |absolute|
            try connectStreamAttemptBefore(
                allocator,
                io,
                stream,
                null,
                connect_options,
                absolute,
            )
        else
            try connectStreamAttempt(
                allocator,
                io,
                stream,
                null,
                connect_options,
            );
        stream_owned = false;
        return attempt;
    }

    fn connectStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        return connectStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            null,
        );
    }

    fn connectStreamAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            deadline,
        );
    }

    fn connectStreamAttemptMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        try socket_options.applyTcp(stream, .{
            .no_delay = options.tcp_nodelay,
            .keep_alive = options.tcp_keepalive,
            .user_timeout_ms = options.tcp_user_timeout_ms,
        });
        const transport: RuntimeTransport = if (tls_conn) |conn| .{ .tls = conn } else .{ .tcp = .{ .io = io, .stream = stream } };
        return connectTransportAttempt(
            allocator,
            io,
            transport,
            options,
            deadline,
        );
    }

    fn closeRejectedAttempt(attempt: *ConnectAttempt) ConnectAttempt {
        if (!attempt.accepted()) {
            attempt.transport.?.close();
            attempt.transport = null;
        }
        return attempt.*;
    }

    fn connectTransportAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        transport: RuntimeTransport,
        options: ConnectOptions,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const deadline = deadline_policy.earlier(
            outer_deadline,
            if (options.limits.http1_handshake_timeout) |timeout|
                try handshakeDeadline(transport, timeout)
            else
                null,
        );
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(io, absolute);
        var nonce: [16]u8 = undefined;
        try std.Io.randomSecure(io, &nonce);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &nonce);

        var protocol_value_stack: [handshake_headers.protocol_value_stack_capacity]u8 = undefined;
        var protocol_value = try handshake_headers.prepareProtocolValue(
            allocator,
            options.protocols,
            &protocol_value_stack,
        );
        defer protocol_value.deinit(allocator);
        try validateHttp1ClientExtraHeadersImpl(options.extra_headers);
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
            .context_takeover = options.context_takeover,
        };
        var extension_offer_storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
        const extension_offer = try websocket.ExtensionNegotiation
            .offerValueInto(
            &extension_offer_storage,
            extension_policy,
            options.client_max_window_bits,
            options.server_max_window_bits,
        );
        const headers_count = std.math.add(
            usize,
            4 + @as(usize, @intFromBool(protocol_value.value.len != 0)) +
                @as(usize, @intFromBool(options.origin != null)) +
                @as(usize, @intFromBool(extension_offer != null)),
            options.extra_headers.len,
        ) catch return error.HeadersTooLarge;
        var headers_stack: [handshake_storage.stack_capacity]http1.Header =
            undefined;
        const headers = try handshake_storage.acquire(
            http1.Header,
            allocator,
            &headers_stack,
            headers_count,
        );
        defer handshake_storage.release(
            http1.Header,
            allocator,
            &headers_stack,
            headers,
        );
        var header_index: usize = 0;
        headers[header_index] = .{ .name = "Upgrade", .value = "websocket" };
        header_index += 1;
        headers[header_index] = .{ .name = "Connection", .value = "Upgrade" };
        header_index += 1;
        headers[header_index] = .{ .name = "Sec-WebSocket-Key", .value = &key };
        header_index += 1;
        headers[header_index] = .{ .name = "Sec-WebSocket-Version", .value = "13" };
        header_index += 1;
        if (protocol_value.value.len != 0) {
            headers[header_index] = .{
                .name = "Sec-WebSocket-Protocol",
                .value = protocol_value.value,
            };
            header_index += 1;
        }
        if (options.origin) |origin| {
            headers[header_index] = .{ .name = "Origin", .value = origin };
            header_index += 1;
        }
        if (extension_offer) |value| {
            headers[header_index] = .{
                .name = "Sec-WebSocket-Extensions",
                .value = value,
            };
            header_index += 1;
        }
        @memcpy(headers[header_index..], options.extra_headers);
        try handshake_request.write(
            allocator,
            .{
                .method = .GET,
                .target = options.target,
                .host = options.host,
                .headers = headers,
            },
            options.limits.max_head_bytes,
            HandshakeWriter{ .transport = transport, .deadline = deadline },
            HandshakeWriter.write,
        );

        var head = try readHttpHeadFromTransport(
            allocator,
            transport,
            options.limits.max_head_bytes,
            deadline,
        );
        var head_owned = true;
        defer if (head_owned) head.deinit(allocator);
        var informational_count: usize = 0;
        while (true) {
            var response_header_stack: [handshake_storage.stack_capacity]http1.Header =
                undefined;
            const response_headers = try handshake_storage.acquire(
                http1.Header,
                allocator,
                &response_header_stack,
                options.limits.max_response_headers,
            );
            defer handshake_storage.release(
                http1.Header,
                allocator,
                &response_header_stack,
                response_headers,
            );
            const response_head = try http1.parseResponseHead(
                head.head,
                response_headers,
                http1HandshakeResponseParseOptions(options.limits),
                .{ .request_method = .GET },
            );
            if (response_head.status < 100 or
                response_head.status >= 200 or
                response_head.status == 101)
            {
                break;
            }
            try http1.validateResponseBodyForStatus(
                response_head.status,
                response_head.headers,
                &.{},
                &.{},
            );
            informational_count += 1;
            if (informational_count >
                options.limits.max_informational_responses)
            {
                return error.TooManyInformationalResponses;
            }
            const next = try readHttpHeadFromTransportWithInitial(
                allocator,
                transport,
                options.limits.max_head_bytes,
                deadline,
                head.extra,
            );
            head.deinit(allocator);
            head = next;
        }
        const response_bytes = try readHttpUpgradeResponseBytes(
            allocator,
            transport,
            &head,
            options.limits,
            deadline,
        );
        if (response_bytes.extra != null) head_owned = false;
        errdefer allocator.free(response_bytes.bytes);
        errdefer if (response_bytes.extra) |extra| allocator.free(extra);
        var response = try http1.parseResponse(
            allocator,
            response_bytes.bytes,
            http1HandshakeResponseParseOptions(options.limits),
        );
        errdefer response.deinit(allocator);
        if (response.status != 101 and
            http1_message_framing.responseHeadUsesCloseDelimitedBody(
                head.head[0 .. head.head.len - 4],
                .GET,
            ))
        {
            response.body = response_bytes.bytes[head.head.len..];
            response.body_framing = .close_delimited;
            response.consumed = response_bytes.bytes.len;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .transport = transport,
            .response_bytes = response_bytes.bytes,
            .response = response,
            .initial_websocket_bytes = response_bytes.extra,
            .key = key,
            .protocols = options.protocols,
            .require_subprotocol = options.require_subprotocol,
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
            .context_takeover = options.context_takeover,
            .client_max_window_bits = options.client_max_window_bits,
            .server_max_window_bits = options.server_max_window_bits,
            .compression_threshold = options.compression_threshold,
            .limits = options.limits,
        };
    }
};

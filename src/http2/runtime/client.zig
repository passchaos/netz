//! HTTP/2 client connection establishment and request execution.

const std = @import("std");
const http2 = @import("../mod.zig");
const http1 = @import("../../http1/mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const accept_deadline = @import("../../internal/accept.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const client_authority = @import("client/authority.zig");
const client_duplex_owner = @import("duplex/client_owner.zig");
const DuplexOwners = @import("duplex/owners.zig").Owners;
const duplex_wake = @import("duplex/wake.zig");
const frame_io = @import("frame/io.zig");
const socket_options = @import("../../internal/socket_options.zig");

const Error = runtime.Error;
const Limits = runtime.Limits;
const Connection = runtime.Connection;
const RuntimeTransport = runtime.RuntimeTransport;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const tcpTransport = runtime.tcpTransport;
const connectionHandshakeDeadline = runtime.connectionHandshakeDeadline;
const connectionHandshakeDeadlineBefore = runtime.connectionHandshakeDeadlineBefore;
const readSome = runtime.readSome;
const writeAllToStream = runtime.writeAllToStream;
const validateLocalLimits = runtime.validateLocalLimits;
const TlsConnectOptions = runtime.TlsConnectOptions;
const HttpConnectProxy = runtime.HttpConnectProxy;
const RequestOptions = runtime.RequestOptions;
const terminal_tls_output = @import("control/tls_close.zig");
const tcp_connect = @import("../../internal/tcp_connect.zig");
const endpoint_host = @import("../../internal/endpoint_host.zig");
const host_connect = @import("client/host_connect.zig");
const ResponseTimeoutError = runtime.ResponseTimeoutError;
const OwnedResponse = runtime.OwnedResponse;
const H2cUpgradeResult = runtime.H2cUpgradeResult;
const RedirectOptions = runtime.RedirectOptions;
const uriTargetAlloc = runtime.uriTargetAlloc;
const bootstrap_output = @import("connect/bootstrap_output.zig");
const handshake_protocol_error = @import("connect/protocol_error.zig");
const flag_ack = runtime.flag_ack;
const RedirectedResponse = runtime.RedirectedResponse;
const settingsForLimits = runtime.settingsForLimits;
const writeInitialSettingsTransportMaybeBefore = runtime.writeInitialSettingsTransportMaybeBefore;
const writeInitialConnectionWindowTransportMaybeBefore = runtime.writeInitialConnectionWindowTransportMaybeBefore;
const max_settings_payload_len = runtime.max_settings_payload_len;
const uri_redirect = @import("../../http1/runtime/redirect.zig");
const encodeSettingsPayloadInto = runtime.encodeSettingsPayloadInto;
const redirectLocation = runtime.redirectLocation;
const redirectH2Headers = runtime.redirectH2Headers;
const validateHeaderBlock = runtime.validateHeaderBlock;
const limitsToHttp1 = runtime.limitsToHttp1;
const containsHttpToken = runtime.containsHttpToken;

pub const Client = struct {
    /// Adopt an already connected cleartext stream and perform the HTTP/2
    /// prior-knowledge preface/SETTINGS bootstrap. Ownership transfers at
    /// entry; the authority is copied for later requests.
    pub fn adoptPriorKnowledgeStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        authority: []const u8,
        limits: Limits,
    ) Error!Connection {
        if (authority.len == 0) {
            stream.close(io);
            return error.InvalidHeader;
        }
        var connection = try connectStream(allocator, io, stream, limits);
        errdefer connection.close();
        connection.default_authority = try allocator.dupe(u8, authority);
        connection.default_scheme = "http";
        return connection;
    }

    pub fn adoptPriorKnowledgeStreamWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        authority: []const u8,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        if (authority.len == 0) {
            stream.close(io);
            return error.InvalidHeader;
        }
        var connection = try connectStreamBefore(
            allocator,
            io,
            stream,
            limits,
            deadline,
        );
        errdefer connection.close();
        connection.default_authority = try allocator.dupe(u8, authority);
        connection.default_scheme = "http";
        return connection;
    }

    /// A non-positive relative timeout is rejected before ownership transfer.
    pub fn adoptPriorKnowledgeStreamWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        authority: []const u8,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return adoptPriorKnowledgeStreamWithDeadline(
            allocator,
            io,
            stream,
            authority,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Perform origin-authenticated TLS and HTTP/2 bootstrap on a
    /// caller-connected TCP stream. Ownership transfers at entry; `tls_host`
    /// remains the certificate/SNI identity while `authority` is copied for
    /// later requests.
    pub fn adoptTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
    ) Error!Connection {
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
        tls_options: TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
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

    /// A non-positive relative timeout is rejected before ownership transfer.
    pub fn adoptTlsStreamWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
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
        tls_options: TlsConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        try validateLocalLimits(limits);
        const identity = try endpoint_host.parse(tls_host, 443);
        if (authority.len == 0) return error.InvalidHeader;
        const owned_authority = try allocator.dupe(u8, authority);
        stream_owned = false;
        return if (deadline) |absolute|
            connectTlsStreamBefore(
                allocator,
                io,
                stream,
                identity.host,
                owned_authority,
                limits,
                tls_options,
                absolute,
            )
        else
            connectTlsStream(
                allocator,
                io,
                stream,
                identity.host,
                owned_authority,
                limits,
                tls_options,
            );
    }

    /// Adopt a certificate-verified TLS connection already negotiated as
    /// `h2`, then complete the HTTP/2 bootstrap. Ownership transfers at entry.
    pub fn adoptNegotiatedTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        tls_connection: *tls_stream.ClientConnection,
        authority: []const u8,
        limits: Limits,
    ) Error!Connection {
        return adoptNegotiatedTlsMaybeBefore(
            allocator,
            io,
            tls_connection,
            authority,
            limits,
            null,
        );
    }

    pub fn adoptNegotiatedTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        tls_connection: *tls_stream.ClientConnection,
        authority: []const u8,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(io, deadline);
        return adoptNegotiatedTlsMaybeBefore(
            allocator,
            io,
            tls_connection,
            authority,
            limits,
            deadline,
        );
    }

    /// A non-positive relative timeout is rejected before ownership transfer.
    pub fn adoptNegotiatedTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        tls_connection: *tls_stream.ClientConnection,
        authority: []const u8,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return adoptNegotiatedTlsWithDeadline(
            allocator,
            io,
            tls_connection,
            authority,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn adoptNegotiatedTlsMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        tls_connection: *tls_stream.ClientConnection,
        authority: []const u8,
        limits: Limits,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var tls_owned = true;
        errdefer if (tls_owned) {
            const transport = RuntimeTransport{ .tls_client = tls_connection };
            transport.closeWithTerminalBudget(io, limits);
        };
        try validateLocalLimits(limits);
        if (authority.len == 0) return error.InvalidHeader;
        const selected = tls_connection.negotiatedAlpn() orelse
            return error.InvalidAlpn;
        if (!std.mem.eql(u8, selected, "h2")) return error.InvalidAlpn;
        if (limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(tls_connection.stream);
        }
        const owned_authority = try allocator.dupe(u8, authority);
        errdefer allocator.free(owned_authority);
        tls_owned = false;
        var connection = if (deadline) |absolute|
            try connectTransportBefore(
                allocator,
                io,
                tls_connection.stream,
                .{ .tls_client = tls_connection },
                limits,
                absolute,
            )
        else
            try connectTransport(
                allocator,
                io,
                tls_connection.stream,
                .{ .tls_client = tls_connection },
                limits,
            );
        connection.default_authority = owned_authority;
        connection.default_scheme = "https";
        return connection;
    }

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Connection {
        try validateLocalLimits(limits);
        const connect_deadline = try deadline_policy.fromTimeout(io, limits.connect_timeout);
        const authority = try client_authority.ipAlloc(allocator, address);
        errdefer allocator.free(authority);
        const stream = if (connect_deadline) |deadline|
            try tcp_connect.ipWithDeadlineAndOptions(io, address, deadline, limits)
        else
            try tcp_connect.ipWithOptions(io, address, null, limits);
        var connection = try connectStream(allocator, io, stream, limits);
        connection.default_authority = authority;
        connection.default_authority_is_ip = true;
        connection.default_scheme = "http";
        return connection;
    }

    /// Establish TCP and complete the HTTP/2 SETTINGS exchange under one
    /// caller-owned deadline while retaining stricter configured phase limits.
    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const connect_deadline = try deadline_policy.capTimeout(io, deadline, limits.connect_timeout);
        const authority = try client_authority.ipAlloc(allocator, address);
        errdefer allocator.free(authority);
        const stream = try tcp_connect.ipWithDeadlineAndOptions(
            io,
            address,
            connect_deadline,
            limits,
        );
        var connection = try connectStreamBefore(
            allocator,
            io,
            stream,
            limits,
            deadline,
        );
        connection.default_authority = authority;
        connection.default_authority_is_ip = true;
        connection.default_scheme = "http";
        return connection;
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            address,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect with HTTP/2 prior knowledge over a Unix-domain stream.
    /// `authority` is copied for subsequent requests that omit it; the local
    /// transport still uses the `http` scheme and skips TCP-only NODELAY.
    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        authority: []const u8,
        limits: Limits,
    ) Error!Connection {
        try validateLocalLimits(limits);
        if (authority.len == 0) return error.InvalidHeader;
        const owned_authority = try allocator.dupe(u8, authority);
        errdefer allocator.free(owned_authority);
        try tcp_connect.validateUnixOptions(limits);
        const stream = try tcp_connect.unix(io, address, limits.connect_timeout);
        var connection = try connectStreamWithoutTcpOptions(
            allocator,
            io,
            stream,
            limits,
        );
        connection.default_authority = owned_authority;
        connection.default_scheme = "http";
        return connection;
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        authority: []const u8,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        try validateLocalLimits(limits);
        if (authority.len == 0) return error.InvalidHeader;
        const owned_authority = try allocator.dupe(u8, authority);
        errdefer allocator.free(owned_authority);
        try tcp_connect.validateUnixOptions(limits);
        const stream = try tcp_connect.unixWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        var connection = try connectStreamWithoutTcpOptionsBefore(
            allocator,
            io,
            stream,
            limits,
            deadline,
        );
        connection.default_authority = owned_authority;
        connection.default_scheme = "http";
        return connection;
    }

    pub fn connectUnixWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        authority: []const u8,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithDeadline(
            allocator,
            io,
            address,
            authority,
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
    ) Error!Connection {
        try validateLocalLimits(limits);
        const opened = try host_connect.open(allocator, io, host, port, limits, null);
        errdefer allocator.free(opened.authority);
        var connection = try connectStream(allocator, io, opened.stream, limits);
        connection.default_authority = opened.authority;
        connection.default_scheme = "http";
        return connection;
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const opened = try host_connect.open(allocator, io, host, port, limits, deadline);
        errdefer allocator.free(opened.authority);
        var connection = try connectStreamBefore(
            allocator,
            io,
            opened.stream,
            limits,
            deadline,
        );
        connection.default_authority = opened.authority;
        connection.default_scheme = "http";
        return connection;
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Connection {
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
        tls_options: TlsConnectOptions,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const opened = try host_connect.open(allocator, io, host, port, limits, null);
        // connectTlsStream assumes both resources at entry and provides the
        // only cleanup path after this transfer.
        return connectTlsStream(
            allocator,
            io,
            opened.stream,
            opened.identity,
            opened.authority,
            limits,
            tls_options,
        );
    }

    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const opened = try host_connect.open(allocator, io, host, port, limits, deadline);
        return connectTlsStreamBefore(
            allocator,
            io,
            opened.stream,
            opened.identity,
            opened.authority,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
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

    /// Establish TLS HTTP/2 through one HTTP/1.1 CONNECT proxy. The origin
    /// hostname is resolved by the proxy, while TLS identity, SNI and
    /// :authority remain bound to `host` and `port`.
    pub fn connectTlsHostViaProxy(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        proxy: HttpConnectProxy,
        limits: Limits,
        tls_options: TlsConnectOptions,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const parsed = try endpoint_host.parse(host, port);
        const authority = try parsed.authorityAlloc(allocator, port);
        var authority_owned = true;
        errdefer if (authority_owned) allocator.free(authority);
        var proxy_limits = proxy.limits;
        if (limits.local_address) |address| proxy_limits.local_address = address;
        if (limits.network_interface) |interface| proxy_limits.network_interface = interface;
        if (limits.address_resolver) |resolver| proxy_limits.address_resolver = resolver;
        if (limits.address_connect_policy) |policy| proxy_limits.address_connect_policy = policy;
        const stream = try http1_runtime.Client.connectTunnelViaProxyUri(
            allocator,
            io,
            proxy.uri,
            proxy.tunnel_authority orelse authority,
            proxy.options,
            proxy_limits,
        );
        authority_owned = false;
        return connectTlsStream(
            allocator,
            io,
            stream,
            parsed.host,
            authority,
            limits,
            tls_options,
        );
    }

    /// Preserve one absolute budget across proxy resolution/TCP/CONNECT,
    /// origin TLS authentication with h2 ALPN, and HTTP/2 bootstrap.
    pub fn connectTlsHostViaProxyWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        proxy: HttpConnectProxy,
        limits: Limits,
        tls_options: TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        try validateLocalLimits(limits);
        _ = try deadline_policy.usableAwake(io, deadline);
        const parsed = try endpoint_host.parse(host, port);
        const authority = try parsed.authorityAlloc(allocator, port);
        var authority_owned = true;
        errdefer if (authority_owned) allocator.free(authority);
        var proxy_limits = proxy.limits;
        if (limits.local_address) |address| proxy_limits.local_address = address;
        if (limits.network_interface) |interface| proxy_limits.network_interface = interface;
        if (limits.address_resolver) |resolver| proxy_limits.address_resolver = resolver;
        if (limits.address_connect_policy) |policy| proxy_limits.address_connect_policy = policy;
        const stream = try http1_runtime.Client
            .connectTunnelViaProxyUriWithDeadline(
            allocator,
            io,
            proxy.uri,
            proxy.tunnel_authority orelse authority,
            proxy.options,
            proxy_limits,
            deadline,
        );
        authority_owned = false;
        return connectTlsStreamBefore(
            allocator,
            io,
            stream,
            parsed.host,
            authority,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectTlsHostViaProxyWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        proxy: HttpConnectProxy,
        limits: Limits,
        tls_options: TlsConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostViaProxyWithDeadline(
            allocator,
            io,
            host,
            port,
            proxy,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect to an already resolved address while verifying TLS against a
    /// separate DNS or IP identity. This keeps service discovery and certificate/SNI
    /// identity independent without weakening mandatory HTTP/2 ALPN checks.
    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const identity = try endpoint_host.parse(tls_host, address.getPort());
        if (authority.len == 0) return error.InvalidHeader;
        const stream = try tcp_connect.ipWithOptions(io, address, limits.connect_timeout, limits);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const owned_authority = try allocator.dupe(u8, authority);
        var authority_owned = true;
        errdefer if (authority_owned) allocator.free(owned_authority);
        stream_owned = false;
        authority_owned = false;
        return connectTlsStream(
            allocator,
            io,
            stream,
            identity.host,
            owned_authority,
            limits,
            tls_options,
        );
    }

    pub fn connectTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const identity = try endpoint_host.parse(tls_host, address.getPort());
        if (authority.len == 0) return error.InvalidHeader;
        const stream = try tcp_connect.ipWithDeadlineAndOptions(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
            limits,
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const owned_authority = try allocator.dupe(u8, authority);
        var authority_owned = true;
        errdefer if (authority_owned) allocator.free(owned_authority);
        stream_owned = false;
        authority_owned = false;
        return connectTlsStreamBefore(
            allocator,
            io,
            stream,
            identity.host,
            owned_authority,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
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

    /// Own the TCP stream and authority from entry. Centralizing this state
    /// transition keeps address- and hostname-based TLS connections aligned
    /// on NODELAY, ALPN validation, HTTP/2 preface, and error cleanup.
    fn connectTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        owned_authority: []u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
    ) Error!Connection {
        return connectTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            owned_authority,
            limits,
            tls_options,
            null,
        );
    }

    fn connectTlsStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        owned_authority: []u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            owned_authority,
            limits,
            tls_options,
            deadline,
        );
    }

    fn connectTlsStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        owned_authority: []u8,
        limits: Limits,
        tls_options: TlsConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        errdefer allocator.free(owned_authority);
        if (deadline) |until| _ = try deadline_policy.usableAwake(io, until);
        if (limits.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
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
        var tls_owned = true;
        errdefer if (tls_owned) {
            const transport = RuntimeTransport{ .tls_client = tls_connection };
            transport.closeWithTerminalBudget(io, limits);
        };
        if (tls_connection.selected_alpn == null or
            !std.mem.eql(u8, tls_connection.selected_alpn.?, "h2"))
        {
            return error.InvalidAlpn;
        }
        // connectTransport owns the TLS connection on every return path.
        tls_owned = false;
        var connection = if (deadline) |absolute|
            try connectTransportBefore(
                allocator,
                io,
                stream,
                .{ .tls_client = tls_connection },
                limits,
                absolute,
            )
        else
            try connectTransport(
                allocator,
                io,
                stream,
                .{ .tls_client = tls_connection },
                limits,
            );
        connection.default_authority = owned_authority;
        connection.default_scheme = "https";
        return connection;
    }

    /// Perform an RFC 7540 h2c Upgrade request and return the response on
    /// stream 1. `request_options` must include an authority (or Host header)
    /// because the opening request is first sent as HTTP/1.1.
    pub fn connectUpgrade(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        request_options: RequestOptions,
    ) Error!OwnedResponse {
        try validateLocalLimits(limits);
        const stream = try tcp_connect.ipWithOptions(io, address, limits.connect_timeout, limits);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        // connectStreamUpgrade takes ownership at entry and closes the stream
        // through its partially built Connection on every failure.
        stream_owned = false;
        var upgraded = try connectStreamUpgrade(allocator, io, stream, limits, request_options);
        defer upgraded.deinit(allocator);
        return upgraded.connection.readResponse(
            1,
            request_options.method,
            request_options.protocol != null,
            null,
        );
    }

    /// Apply one absolute deadline to TCP establishment, the HTTP/1.1 Upgrade
    /// response, HTTP/2 SETTINGS bootstrap, and the complete stream-1 response.
    pub fn connectUpgradeWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        request_options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        try validateLocalLimits(limits);
        const stream = try tcp_connect.ipWithDeadlineAndOptions(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
            limits,
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        stream_owned = false;
        var upgraded = try connectStreamUpgradeWithDeadline(
            allocator,
            io,
            stream,
            limits,
            request_options,
            deadline,
        );
        defer upgraded.deinit(allocator);
        return upgraded.connection.readResponseWithDeadline(
            1,
            request_options.method,
            request_options.protocol != null,
            deadline,
        );
    }

    pub fn connectUpgradeWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        request_options: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUpgradeWithDeadline(
            allocator,
            io,
            address,
            limits,
            request_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriUpgrade(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedScheme;
        try tcp_connect.validateAddressConnectPolicy(limits.address_connect_policy orelse .ordered);
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, 80);
        defer endpoint.deinit();

        try validateLocalLimits(limits);
        const stream = try tcp_connect.endpointWithOptions(
            allocator,
            io,
            switch (endpoint.target) {
                .ip => |address| address,
                .host => null,
            },
            endpoint.tls_host,
            endpoint.port,
            limits.address_resolver,
            limits.address_connect_policy orelse .ordered,
            try deadline_policy.fromTimeout(io, limits.connect_timeout),
            .fromOptions(limits),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var options = request_options;
        options.path = target;
        if (options.authority == null) options.authority = endpoint.authority;
        if (options.scheme == null) options.scheme = uri.scheme;
        // Transfer before the call so its error cleanup is the sole owner.
        stream_owned = false;
        var upgraded = try connectStreamUpgrade(allocator, io, stream, limits, options);
        defer upgraded.deinit(allocator);
        return upgraded.connection.readResponse(
            1,
            options.method,
            options.protocol != null,
            null,
        );
    }

    /// URI counterpart to `connectUpgradeWithDeadline`; DNS and every address
    /// attempt consume the same budget before h2c negotiation and response I/O.
    pub fn requestUriUpgradeWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) {
            return error.UnsupportedScheme;
        }
        try tcp_connect.validateAddressConnectPolicy(limits.address_connect_policy orelse .ordered);
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, 80);
        defer endpoint.deinit();
        try validateLocalLimits(limits);
        const network_deadline = try deadline_policy.capTimeout(
            io,
            deadline,
            limits.connect_timeout,
        );
        const stream = try tcp_connect.endpointWithOptions(
            allocator,
            io,
            switch (endpoint.target) {
                .ip => |address| address,
                .host => null,
            },
            endpoint.tls_host,
            endpoint.port,
            limits.address_resolver,
            limits.address_connect_policy orelse .ordered,
            network_deadline,
            .fromOptions(limits),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var options = request_options;
        options.path = target;
        if (options.authority == null) options.authority = endpoint.authority;
        if (options.scheme == null) options.scheme = uri.scheme;
        stream_owned = false;
        var upgraded = try connectStreamUpgradeWithDeadline(
            allocator,
            io,
            stream,
            limits,
            options,
            deadline,
        );
        defer upgraded.deinit(allocator);
        return upgraded.connection.readResponseWithDeadline(
            1,
            options.method,
            options.protocol != null,
            deadline,
        );
    }

    pub fn requestUriUpgradeWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriUpgradeWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Upgrade an existing cleartext HTTP/1.1 stream to HTTP/2 and return the
    /// established connection plus the consumed 101 response metadata.  The
    /// stream transfers at entry and every failure closes it. The caller owns
    /// both returned values and should call `H2cUpgradeResult.deinit` or
    /// close/deinit each field manually after taking ownership.
    pub fn connectStreamUpgrade(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        request_options: RequestOptions,
    ) Error!H2cUpgradeResult {
        return connectStreamUpgradeMaybeBefore(
            allocator,
            io,
            stream,
            limits,
            request_options,
            null,
        );
    }

    /// Transfer `stream` into an h2c connection under one caller-owned
    /// awake-clock deadline spanning the HTTP/1.1 101 response and HTTP/2
    /// SETTINGS bootstrap. Configured handshake limits may shorten the wait.
    /// Ownership transfers at entry, including invalid/expired deadlines.
    pub fn connectStreamUpgradeWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        request_options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2cUpgradeResult {
        return connectStreamUpgradeMaybeBefore(
            allocator,
            io,
            stream,
            limits,
            request_options,
            deadline,
        );
    }

    fn connectStreamUpgradeMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        request_options: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!H2cUpgradeResult {
        // This entry point owns the stream immediately. Constructing the
        // Connection first gives validation, allocation, and both handshake
        // variants one authoritative failure-close path.
        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .transport = tcpTransport(io, stream),
            .role = .client,
            .limits = limits,
            .last_peer_frame_at = std.Io.Clock.awake.now(io),
            .awaiting_settings_ack = true,
            .next_client_stream_id = 3,
            .default_scheme = "http",
        };
        errdefer connection.close();
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(io, absolute);
        }
        try validateLocalLimits(limits);
        if (limits.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
        connection.applyLocalLimits();

        const transport = connection.transportForIo();
        const http1_deadline = if (deadline) |absolute|
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

        const h2c_settings = try settingsForLimits(limits, .client);
        var settings_payload_buf: [max_settings_payload_len]u8 = undefined;
        const settings_payload = try encodeSettingsPayloadInto(
            &settings_payload_buf,
            h2c_settings.buf[0..h2c_settings.count],
        );
        const settings_value = try allocator.alloc(
            u8,
            std.base64.url_safe_no_pad.Encoder.calcSize(settings_payload.len),
        );
        defer allocator.free(settings_value);
        _ = std.base64.url_safe_no_pad.Encoder.encode(
            settings_value,
            settings_payload,
        );

        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(allocator);
        if (request_options.authority) |authority| {
            try headers.append(allocator, .{
                .name = "Host",
                .value = authority,
            });
        }
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            try headers.append(allocator, .{
                .name = "Priority",
                .value = value.serialize(&priority_buf),
            });
        }
        try headers.appendSlice(allocator, &.{
            .{ .name = "Connection", .value = "Upgrade, HTTP2-Settings" },
            .{ .name = "Upgrade", .value = "h2c" },
            .{ .name = "HTTP2-Settings", .value = settings_value },
        });
        for (request_options.headers) |header| {
            try headers.append(allocator, .{
                .name = header.name,
                .value = header.value,
            });
        }
        try validateHeaderBlock(request_options.trailers, .request_trailers);
        var trailers: std.ArrayList(http1.Header) = .empty;
        defer trailers.deinit(allocator);
        try trailers.ensureTotalCapacity(
            allocator,
            request_options.trailers.len,
        );
        for (request_options.trailers) |trailer| {
            trailers.appendAssumeCapacity(.{
                .name = trailer.name,
                .value = trailer.value,
            });
        }
        const method = http1.Method.parse(request_options.method) catch
            return error.InvalidHeader;
        // RFC 7540 section 3.2 assigns the complete HTTP/1.1 request, including
        // any entity body and trailers, to half-closed stream 1. CONNECT is not
        // an Upgrade-capable HTTP/1.1 request and retains its tunnel API.
        if (method == .CONNECT) return error.InvalidHeader;
        const upgrade_request: http1_runtime.RequestOptions = .{
            .method = method,
            .target = request_options.path,
            .headers = headers.items,
            .body = request_options.body,
            .trailers = trailers.items,
        };
        if (http1_deadline) |absolute| {
            try http1_runtime.writeRequestToStreamWithDeadline(
                allocator,
                io,
                stream,
                upgrade_request,
                absolute,
            );
        } else {
            try http1_runtime.writeRequestToStream(
                allocator,
                io,
                stream,
                upgrade_request,
            );
        }
        var upgrade = if (http1_deadline) |absolute|
            try http1_runtime.readResponseFromStreamForRequestWithDeadline(
                allocator,
                io,
                stream,
                limitsToHttp1(limits),
                .{},
                method,
                absolute,
            )
        else
            try http1_runtime.readResponseFromStreamForRequest(
                allocator,
                io,
                stream,
                limitsToHttp1(limits),
                .{},
                method,
            );
        errdefer upgrade.deinit(allocator);
        if (upgrade.response.status != 101) return error.InvalidResponse;
        const connection_header = upgrade.response.header("connection") orelse
            return error.InvalidResponse;
        const upgrade_header = upgrade.response.header("upgrade") orelse
            return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, upgrade_header, " \t"),
            "h2c",
        )) return error.InvalidResponse;
        if (!containsHttpToken(connection_header, "upgrade")) {
            return error.InvalidResponse;
        }

        // Legacy calls deliberately start their SETTINGS phase budget after
        // validating 101. Deadline calls instead retain the original timestamp
        // and cap it with the possibly stricter phase limit.
        const handshake_deadline = if (deadline) |absolute|
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
        try bootstrap_output.writeClientPreface(transport, handshake_deadline);
        try bootstrap_output.writeFrame(
            allocator,
            transport,
            .settings,
            0,
            0,
            settings_payload,
            handshake_deadline,
        );
        try finishClientSettingsHandshake(&connection, handshake_deadline);
        try writeInitialConnectionWindowTransportMaybeBefore(allocator, transport, limits, handshake_deadline);
        return .{ .connection = connection, .upgrade_response = upgrade };
    }

    /// Ownership transfers at entry, including non-positive timeouts.
    pub fn connectStreamUpgradeWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        request_options: RequestOptions,
        timeout: std.Io.Duration,
    ) Error!H2cUpgradeResult {
        if (timeout.nanoseconds <= 0) {
            stream.close(io);
            return error.Timeout;
        }
        return connectStreamUpgradeWithDeadline(
            allocator,
            io,
            stream,
            limits,
            request_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        stream_owned = false;
        return connectStreamWithoutTcpOptions(
            allocator,
            io,
            stream,
            limits,
        );
    }

    fn connectStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
        stream_owned = false;
        return connectStreamWithoutTcpOptionsBefore(
            allocator,
            io,
            stream,
            limits,
            deadline,
        );
    }

    fn connectStreamWithoutTcpOptions(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
    ) Error!Connection {
        return connectTransport(
            allocator,
            io,
            stream,
            tcpTransport(io, stream),
            limits,
        );
    }

    fn connectStreamWithoutTcpOptionsBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectTransportBefore(
            allocator,
            io,
            stream,
            tcpTransport(io, stream),
            limits,
            deadline,
        );
    }

    fn connectTransport(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        transport: RuntimeTransport,
        limits: Limits,
    ) Error!Connection {
        return connectTransportMaybeBefore(
            allocator,
            io,
            stream,
            transport,
            limits,
            null,
        );
    }

    fn connectTransportBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        transport: RuntimeTransport,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectTransportMaybeBefore(
            allocator,
            io,
            stream,
            transport,
            limits,
            deadline,
        );
    }

    fn connectTransportMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        transport: RuntimeTransport,
        limits: Limits,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
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
        try bootstrap_output.writeClientPreface(transport, deadline);
        try writeInitialSettingsTransportMaybeBefore(allocator, transport, limits, .client, deadline);
        try writeInitialConnectionWindowTransportMaybeBefore(allocator, transport, limits, deadline);

        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .transport = transport,
            .role = .client,
            .limits = limits,
            .last_peer_frame_at = std.Io.Clock.awake.now(io),
            .awaiting_settings_ack = true,
        };
        transport_owned = false;
        connection.applyLocalLimits();
        errdefer connection.close();
        try finishClientSettingsHandshake(&connection, deadline);
        return connection;
    }

    fn finishClientSettingsHandshake(
        connection: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        // Bootstrap failures close the transport rather than renewing a TLS
        // close_notify budget in the caller's Connection destructor.
        errdefer terminal_tls_output.retire(connection.transportForIo());
        var saw_server_settings = false;
        var saw_settings_ack = false;
        while (!saw_server_settings or !saw_settings_ack) {
            var frame = try handshake_protocol_error.readFrame(
                connection.allocator,
                connection.transportForIo(),
                connection.limits,
                deadline,
            );
            defer frame.deinit(connection.allocator);
            if (frame.frame.header.frame_type != .settings) {
                if (try connection.handleConnectionOrGoAwayFrameUntil(frame.frame, deadline)) continue;
                return error.UnexpectedFrame;
            }
            if ((frame.frame.header.flags & flag_ack) != 0) {
                saw_settings_ack = true;
                try connection.applySettingsAck();
            } else {
                saw_server_settings = true;
                try connection.applyPeerSettingsPayload(
                    frame.frame.payload,
                    deadline,
                );
                try bootstrap_output.writeFrame(
                    connection.allocator,
                    connection.transportForIo(),
                    .settings,
                    flag_ack,
                    0,
                    &.{},
                    deadline,
                );
                connection.webtransport_settings.acknowledgePeer();
            }
        }
    }

    pub fn requestUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
    ) ResponseTimeoutError!OwnedResponse {
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
    ) ResponseTimeoutError!RedirectedResponse {
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

    pub fn requestUriFollowingRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
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
    ) ResponseTimeoutError!RedirectedResponse {
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
    ) ResponseTimeoutError!OwnedResponse {
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
    ) ResponseTimeoutError!RedirectedResponse {
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
    ) ResponseTimeoutError!RedirectedResponse {
        var chain = uri_redirect.Chain.init(
            allocator,
            redirect_options.policy,
        );
        defer chain.deinit();
        try chain.recordInitial(uri_text);
        var current_uri = try allocator.dupe(u8, uri_text);
        defer allocator.free(current_uri);
        var hop_options = request_options;
        var hop_tls = redirect_options.tls;
        var owned_headers: ?[]http2.Hpack.HeaderField = null;
        defer if (owned_headers) |headers| allocator.free(headers);

        while (true) {
            var response = if (deadline) |absolute|
                try requestUriTlsWithDeadline(
                    allocator,
                    io,
                    current_uri,
                    hop_options,
                    limits,
                    hop_tls,
                    absolute,
                )
            else
                try requestUriTls(
                    allocator,
                    io,
                    current_uri,
                    hop_options,
                    limits,
                    hop_tls,
                );
            errdefer response.deinit(allocator);
            if (!uri_redirect.isRedirectStatus(response.status)) {
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
            const location = try redirectLocation(response.headers);
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
            var next = try chain.follow(current_uri, location.?, response.status);
            var next_owned = true;
            defer if (next_owned) next.deinit();

            const action = uri_redirect.methodActionBytes(
                redirect_options.policy,
                response.status,
                hop_options.method,
            );
            const remove_credentials = next.cross_origin and
                !redirect_options.policy.forward_cross_origin_credentials;
            if (next.cross_origin) {
                try uri_redirect.enforceClientIdentityPolicy(
                    redirect_options.policy,
                    true,
                    hop_tls.client_identity != null,
                );
                hop_tls.tls12_ticket_resumption = null;
                hop_tls.tls13_ticket_resumption = null;
            }
            hop_options.headers = try redirectH2Headers(
                allocator,
                hop_options.headers,
                remove_credentials,
                action == .rewrite_get,
                &owned_headers,
            );
            hop_options.authority = null;
            hop_options.scheme = null;
            if (action == .rewrite_get) {
                hop_options.method = "GET";
                hop_options.protocol = null;
                hop_options.body = &.{};
                hop_options.trailers = &.{};
            } else if (remove_credentials) {
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
        return requestUriTls(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            .{},
        );
    }

    pub fn requestUriTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsConnectOptions,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!is_http and !is_https) return error.UnsupportedScheme;
        try tcp_connect.validateAddressConnectPolicy(limits.address_connect_policy orelse .ordered);
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(
            allocator,
            uri,
            if (is_https) 443 else 80,
        );
        defer endpoint.deinit();

        try validateLocalLimits(limits);
        var connection = if (is_https) switch (endpoint.target) {
            .host => try connectTlsHost(
                allocator,
                io,
                endpoint.tls_host,
                endpoint.port,
                limits,
                tls_options,
            ),
            .ip => |address| try connectTlsAddress(
                allocator,
                io,
                address,
                endpoint.tls_host,
                endpoint.authority,
                limits,
                tls_options,
            ),
        } else blk: {
            const stream = try tcp_connect.endpointWithOptions(
                allocator,
                io,
                switch (endpoint.target) {
                    .ip => |address| address,
                    .host => null,
                },
                endpoint.tls_host,
                endpoint.port,
                limits.address_resolver,
                limits.address_connect_policy orelse .ordered,
                try deadline_policy.fromTimeout(io, limits.connect_timeout),
                .fromOptions(limits),
            );
            var stream_owned = true;
            errdefer if (stream_owned) stream.close(io);
            const established = try connectStream(allocator, io, stream, limits);
            stream_owned = false;
            break :blk established;
        };
        defer connection.close();
        try client_authority.replace(allocator, &connection.default_authority, endpoint.authority);
        connection.default_authority_is_ip = false;
        connection.default_scheme = uri.scheme;
        var options = request_options;
        options.path = target;
        if (options.scheme == null) options.scheme = uri.scheme;
        return connection.request(options);
    }

    pub fn requestUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
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
    ) ResponseTimeoutError!OwnedResponse {
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

    /// Apply one absolute deadline to URI parsing's network work, DNS/TCP,
    /// optional TLS, the HTTP/2 SETTINGS bootstrap, and the complete response.
    /// Configured connect, TLS, and bootstrap timeouts remain stricter bounds.
    pub fn requestUriTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        _ = try deadline_policy.usableAwake(io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!is_http and !is_https) return error.UnsupportedScheme;
        try tcp_connect.validateAddressConnectPolicy(limits.address_connect_policy orelse .ordered);
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(
            allocator,
            uri,
            if (is_https) 443 else 80,
        );
        defer endpoint.deinit();

        try validateLocalLimits(limits);
        var connection = if (is_https) switch (endpoint.target) {
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
            .ip => |address| try connectWithDeadline(
                allocator,
                io,
                address,
                limits,
                deadline,
            ),
        };
        defer connection.close();
        try client_authority.replace(allocator, &connection.default_authority, endpoint.authority);
        connection.default_authority_is_ip = false;
        connection.default_scheme = uri.scheme;
        var options = request_options;
        options.path = target;
        if (options.scheme == null) options.scheme = uri.scheme;
        return connection.requestWithDeadline(options, deadline);
    }

    pub fn requestUriTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsConnectOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
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
};

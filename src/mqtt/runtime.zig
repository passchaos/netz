const std = @import("std");
pub const connack_preparation = @import("runtime/connack.zig");
pub const builtin = @import("builtin");
const mqtt = @import("mod.zig");
pub const redirect = @import("redirect.zig");
const websocket = @import("../websocket/mod.zig");
pub const websocket_runtime = websocket.runtime;
pub const http1_runtime = @import("../http1/mod.zig").runtime;
pub const packet_transport = @import("runtime/packet_transport.zig");
pub const packet_identifiers = @import("runtime/packet_identifiers.zig");
pub const stream_io = @import("../internal/stream_io.zig");
const accept_deadline = @import("../internal/accept.zig");
pub const deadline_policy = @import("../internal/deadline.zig");
pub const auth_runtime = @import("runtime/auth.zig");
pub const termination = @import("runtime/termination.zig");
pub const topic_alias = @import("runtime/topic_alias.zig");
pub const proxy_protocol = @import("proxy_protocol.zig");
pub const listener_namespace = @import("listener_namespace.zig");
pub const tls_stream = @import("../tls/mod.zig").stream;
const socket_options = @import("../internal/socket_options.zig");
const socks5_proxy = @import("../proxy/socks5.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const network_endpoint = @import("runtime/network_endpoint.zig");
const protocol_error = @import("runtime/protocol_error.zig");

const net = std.Io.net;

pub const Error = packet_transport.Error || error{
    PacketTooLarge,
    TooManyPendingPackets,
    UnexpectedPacket,
    ConnectRefused,
    InflightFull,
    ReceiveMaximumExceeded,
    QoSNotSupported,
    RetainNotSupported,
    TopicAliasInvalid,
    WildcardSubscriptionsNotSupported,
    TopicOutsideNamespace,
    SubscriptionIdentifiersNotSupported,
    SharedSubscriptionsNotSupported,
    OutgoingPacketTooLarge,
    PublishRefused,
    SubscriptionRefused,
    InvalidServerReference,
    UnsupportedRedirectScheme,
    RedirectLimitExceeded,
    RedirectLoop,
    RedirectRejected,
    ExporterUnavailable,
    TlsKeyUpdateUnavailable,
    ConnectorDeadlineUnsupported,
    InvalidSocketOption,
    InvalidAddressConnectPolicy,
    SocketOptionFailed,
    SocketOptionUnsupported,
} || auth_runtime.Error || proxy_protocol.Error || socks5_proxy.Error ||
    websocket_runtime.Error ||
    net.IpAddress.ListenError || net.IpAddress.ConnectError ||
    net.UnixAddress.ListenError || net.UnixAddress.ConnectError ||
    net.HostName.ValidateError || net.HostName.ConnectError ||
    net.Server.AcceptError || net.Stream.Reader.Error ||
    net.Stream.Writer.Error || std.Thread.SpawnError;

pub const disconnectReasonForProtocolViolation =
    protocol_error.disconnectReason;
pub const TcpKeepAlive = socket_options.TcpKeepAlive;
pub const AddressResolver = network_endpoint.AddressResolver;
pub const AddressConnectPolicy = network_endpoint.AddressConnectPolicy;
pub const HappyEyeballsOptions = network_endpoint.HappyEyeballsOptions;

/// MQTT 3.1 reserves the complete CONNACK acknowledgement byte. Mosquitto
/// uses bit 0 as the later Session Present field; callers must opt into that
/// extension explicitly on both client and server boundaries.
pub const V31ConnAckMode = enum { strict, mosquitto };

pub const Limits = struct {
    max_packet_size: usize = 16 * 1024 * 1024,
    /// Maximum interleaved Control Packets retained while a synchronous client
    /// operation waits for its correlated response. MQTT permits the broker to
    /// send ordinary traffic at any time, so publishing, SUBSCRIBE,
    /// UNSUBSCRIBE and PING preserve those packets for the next typed reader.
    /// Reaching the bound fails the operation, with one already-consumed
    /// overflow packet retained separately so wire order remains recoverable.
    max_pending_ping_packets: usize = 256,
    /// Complete MQTT wire bytes retained by correlated-response helpers.
    /// One packet already consumed before a quota/allocator failure is kept
    /// separately, bounded by max_packet_size. Zero disables these helpers.
    max_pending_packet_bytes: usize = pending_packets_module.default_max_bytes,
    /// MQTT exchanges many small PUBLISH/PUBACK packets. Disable Nagle by
    /// default so a publisher window does not repeatedly fall onto the Linux
    /// delayed-ACK cliff; callers can opt back into coalescing for WAN bulk
    /// transports.
    tcp_nodelay: bool = true,
    /// Optional TCP keepalive idle, retry interval, and probe-count policy.
    /// Each value is non-zero and expressed in seconds except probe_count.
    tcp_keepalive: ?TcpKeepAlive = null,
    /// Linux TCP_USER_TIMEOUT in milliseconds. Null leaves the kernel default
    /// untouched; zero explicitly restores it. Unsupported transports and
    /// platforms fail rather than silently dropping a configured policy.
    tcp_user_timeout_ms: ?u32 = null,
    /// Require and consume one trusted-proxy header before MQTT CONNECT. This
    /// is opt-in because accepting source metadata from arbitrary peers would
    /// allow address spoofing. `connect_timeout` covers this header and CONNECT
    /// under one absolute admission deadline.
    proxy_protocol: ?proxy_protocol.Version = null,
    /// Require a PROXY v2 SSL TLV whose client_ssl bit is set. This is useful
    /// only behind a trusted TLS-terminating proxy.
    proxy_v2_require_tls: bool = false,
    /// Additionally require the SSL TLV to assert a verified certificate used
    /// on this connection or reused from the proxy's TLS Session.
    proxy_v2_require_client_certificate: bool = false,
    /// Optional absolute budget for receiving the complete PROXY preface.
    /// On raw MQTT TCP this is also capped by the CONNECT admission deadline.
    proxy_header_timeout: ?std.Io.Duration = null,
};

/// Limits consulted after the transport preface and socket setup have
/// completed. Listener-only policy stays in `Limits` instead of being copied
/// into every live MQTT connection.
pub const ConnectionLimits = struct {
    max_packet_size: usize = 16 * 1024 * 1024,
    max_pending_ping_packets: usize = 256,
    max_pending_packet_bytes: usize = pending_packets_module.default_max_bytes,

    pub fn from(limits: Limits) ConnectionLimits {
        return .{
            .max_packet_size = limits.max_packet_size,
            .max_pending_ping_packets = limits.max_pending_ping_packets,
            .max_pending_packet_bytes = limits.max_pending_packet_bytes,
        };
    }
};

pub const ConnectionCapabilities = packed struct(u16) {
    peer_maximum_qos: mqtt.QoS = .exactly_once,
    local_maximum_qos: mqtt.QoS = .exactly_once,
    peer_retain_available: bool = true,
    local_retain_available: bool = true,
    peer_wildcard_subscription_available: bool = true,
    peer_subscription_identifier_available: bool = true,
    peer_shared_subscription_available: bool = true,
    peer_requested_problem_information: bool = true,
    local_wildcard_subscription_available: bool = true,
    local_subscription_identifier_available: bool = true,
    local_shared_subscription_available: bool = true,
    has_incoming_connect_level: bool = false,
    outgoing_retain_enabled: bool = true,
    _padding: u1 = 0,
};

pub fn proxyHeaderDeadline(
    io: std.Io,
    limits: Limits,
) ?std.Io.Clock.Timestamp {
    const timeout = limits.proxy_header_timeout orelse return null;
    return .fromNow(io, .{ .raw = timeout, .clock = .awake });
}

pub fn validateProxyPolicy(limits: Limits) Error!void {
    if ((limits.proxy_v2_require_tls or
        limits.proxy_v2_require_client_certificate) and
        limits.proxy_protocol != .v2)
    {
        return error.InvalidProperty;
    }
    if (limits.proxy_header_timeout) |timeout| {
        if (timeout.nanoseconds <= 0 or limits.proxy_protocol == null) {
            return error.InvalidProperty;
        }
    }
}

/// Consume and validate an optional trusted PROXY preface. Callers transfer
/// the returned metadata into `Connection.attachProxyMetadata`.
pub fn readProxyMetadata(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    outer_deadline: ?std.Io.Clock.Timestamp,
) Error!?proxy_protocol.Metadata {
    const version = limits.proxy_protocol orelse return null;
    var metadata = try proxy_protocol.readWithDeadline(
        allocator,
        io,
        stream,
        version,
        earliestClockDeadline(
            outer_deadline,
            proxyHeaderDeadline(io, limits),
        ),
    );
    errdefer metadata.deinit();
    const tls = metadata.tls;
    if (limits.proxy_v2_require_tls and
        (tls == null or !tls.?.client_ssl))
    {
        return error.InvalidHeader;
    }
    if (limits.proxy_v2_require_client_certificate and
        (tls == null or !tls.?.client_ssl or !tls.?.verified or
            (!tls.?.client_certificate_connection and
                !tls.?.client_certificate_session)))
    {
        return error.InvalidHeader;
    }
    return metadata;
}

pub const PacketTransport = packet_transport.Transport;
pub const broker_keep_alive = @import("runtime/broker_keep_alive.zig");

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: net.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        try validateProxyPolicy(limits);
        return initValidated(
            allocator,
            io,
            try bind_address.listen(io, .{ .reuse_address = true }),
            limits,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers only when
    /// validation succeeds; the returned server closes it from `deinit`.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        limits: Limits,
    ) Error!Server {
        try validateProxyPolicy(limits);
        return initValidated(allocator, io, listener, limits);
    }

    fn initValidated(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        limits: Limits,
    ) Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = listener,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server, options: AcceptOptions) Error!AcceptedClient {
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    /// Accept TCP, then bound trusted PROXY parsing and the complete MQTT
    /// CONNECT admission with one caller-owned awake-clock deadline.
    pub fn acceptWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!AcceptedClient {
        var pending = try self.acceptPendingWithDeadline(options, deadline);
        errdefer pending.deinit(self.allocator);
        return pending.finishWithDeadline(options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptPending(
        self: *Server,
        options: AcceptOptions,
    ) Error!PendingAcceptedClient {
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamPending(stream, options);
    }

    pub fn acceptPendingWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamPendingWithDeadline(
            stream,
            options,
            deadline,
        );
    }

    pub fn acceptPendingWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptPendingWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn pendingSource(self: *Server) PendingSource {
        return .{
            .context = self,
            .accept_pending = struct {
                fn call(
                    context: *anyopaque,
                    options: AcceptOptions,
                ) anyerror!PendingAcceptedClient {
                    const server: *Server = @ptrCast(@alignCast(context));
                    return server.acceptPending(options);
                }
            }.call,
        };
    }

    /// Complete trusted-proxy parsing and MQTT CONNECT on an already accepted
    /// stream. This is also the reusable entry point for broker front ends
    /// that own their accept loop.
    pub fn acceptStreamPending(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!PendingAcceptedClient {
        return self.acceptStreamPendingMaybeBefore(stream, options, null);
    }

    pub fn acceptStreamPendingWithDeadline(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamPendingMaybeBefore(
            stream,
            options,
            deadline,
        );
    }

    pub fn acceptStreamPendingWithTimeout(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingAcceptedClient {
        // Match the deadline form: validation failure leaves the caller-owned
        // accepted stream untouched because ownership has not transferred.
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamPendingWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamPendingMaybeBefore(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        const connect_deadline = deadline_policy.earlier(
            outer_deadline,
            try deadline_policy.fromTimeout(self.io, options.connect_timeout),
        );
        try socket_options.applyTcp(stream, .{
            .no_delay = self.limits.tcp_nodelay,
            .keep_alive = self.limits.tcp_keepalive,
            .user_timeout_ms = self.limits.tcp_user_timeout_ms,
        });
        var proxy_metadata = try readProxyMetadata(
            self.allocator,
            self.io,
            stream,
            self.limits,
            connect_deadline,
        );
        errdefer if (proxy_metadata) |*metadata| metadata.deinit();

        var connection = Connection{
            .allocator = self.allocator,
            .transport = .initTcp(self.io, stream),
            .protocol = options.protocol,
            .limits = .from(self.limits),
            .proxy_v2_require_client_certificate = self.limits.proxy_v2_require_client_certificate,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .incoming_topic_alias_maximum = options.topic_alias_maximum,
        };
        stream_owned = false;
        // After construction, `connection` is the sole stream owner. Its
        // cleanup subsumes the raw accepted-stream cleanup above.
        var connection_owned = true;
        defer if (connection_owned) connection.close();
        if (proxy_metadata) |metadata| {
            try connection.attachProxyMetadata(metadata);
            proxy_metadata = null;
        }
        const pending = try connection.acceptPendingBefore(
            options,
            connect_deadline,
        );
        connection_owned = false;
        return pending;
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *AcceptedClient) Error!void,
        max_connections: usize,
        options: AcceptOptions,
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
            options,
        );
    }

    pub fn serveUntil(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *AcceptedClient,
        ) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveSourceUntil(
            self.pendingSource(),
            self.io,
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

/// MQTT listener over a Unix-domain stream socket.
///
/// It shares the TCP packet/runtime state machine and the Broker's type-erased
/// `PendingSource` boundary. PROXY protocol is rejected because Unix-domain
/// peers already carry local kernel identity rather than an IP hop preface.
pub const UnixServer = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: net.Server,
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
        if (limits.proxy_protocol != null or
            limits.proxy_v2_require_tls or
            limits.proxy_v2_require_client_certificate)
        {
            return error.InvalidProperty;
        }
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

    pub fn accept(
        self: *UnixServer,
        options: AcceptOptions,
    ) Error!AcceptedClient {
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    /// Apply one caller-owned awake-clock deadline to Unix accept and the
    /// complete MQTT CONNECT admission.
    pub fn acceptWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!AcceptedClient {
        var pending = try self.acceptPendingWithDeadline(options, deadline);
        errdefer pending.deinit(self.allocator);
        return pending.finishWithDeadline(options, deadline);
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptPending(
        self: *UnixServer,
        options: AcceptOptions,
    ) Error!PendingAcceptedClient {
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamPendingBefore(stream, options, null);
    }

    pub fn acceptPendingWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamPendingBefore(stream, options, deadline);
    }

    pub fn acceptPendingWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptPendingWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn acceptStreamPendingWithDeadline(
        self: *UnixServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamPendingBefore(stream, options, deadline);
    }

    pub fn acceptStreamPendingWithTimeout(
        self: *UnixServer,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamPendingWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamPendingBefore(
        self: *UnixServer,
        stream: net.Stream,
        options: AcceptOptions,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        var connection = Connection{
            .allocator = self.allocator,
            .transport = .initTcp(self.io, stream),
            .protocol = options.protocol,
            .limits = .from(self.limits),
            .proxy_v2_require_client_certificate = self.limits.proxy_v2_require_client_certificate,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .incoming_topic_alias_maximum = options.topic_alias_maximum,
        };
        errdefer connection.close();
        return if (outer_deadline) |deadline|
            connection.acceptPendingWithDeadline(options, deadline)
        else
            connection.acceptPending(options);
    }

    pub fn pendingSource(self: *UnixServer) PendingSource {
        return .{
            .context = self,
            .accept_pending = struct {
                fn call(
                    context: *anyopaque,
                    options: AcceptOptions,
                ) anyerror!PendingAcceptedClient {
                    const server: *UnixServer = @ptrCast(
                        @alignCast(context),
                    );
                    return server.acceptPending(options);
                }
            }.call,
        };
    }

    /// Accept a bounded set of Unix-domain clients and run their handlers in
    /// parallel. The result ordering matches accept order, just like the TCP
    /// listener, so callers can inspect every connection outcome.
    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *AcceptedClient,
        ) Error!void,
        max_connections: usize,
        options: AcceptOptions,
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
            options,
        );
    }

    pub fn serveUntil(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *AcceptedClient,
        ) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveSourceUntil(
            self.pendingSource(),
            self.io,
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

/// Type-erased pending CONNECT source used by the shared broker core. Keeping
/// transport setup behind one callback lets TCP, TLS, WS and WSS listeners
/// feed the same authorization/Session state machine without importing each
/// other or introducing module cycles.
pub const PendingSource = struct {
    context: *anyopaque,
    accept_pending: *const fn (
        context: *anyopaque,
        options: AcceptOptions,
    ) anyerror!PendingAcceptedClient,

    pub fn acceptPending(
        self: PendingSource,
        options: AcceptOptions,
    ) anyerror!PendingAcceptedClient {
        return self.accept_pending(self.context, options);
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
    /// Setting this event cancels pending accepts and active handler I/O.
    shutdown: *std.Io.Event,
    accept_error_policy: ServeErrorPolicy = .continue_serving,
    connection_error_policy: ServeErrorPolicy = .continue_serving,
    /// Prevent a failed listener from becoming an unbounded retry loop.
    accept_error_backoff: std.Io.Duration = .fromMilliseconds(10),
    error_observer: ?ServeErrorObserver = null,
};

/// Shared finite accept loop for transports that produce `AcceptedClient`.
/// Keeping the task ownership rules in one place prevents TCP and Unix
/// listeners from drifting when connection teardown behavior changes.
fn serveAcceptedConcurrent(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (*HandlerContext, *AcceptedClient) Error!void,
    max_connections: usize,
    options: AcceptOptions,
) AsyncServeError!ConcurrentServeResult {
    var group: std.Io.Group = .init;
    const results = try allocator.alloc(?anyerror, max_connections);
    errdefer allocator.free(results);
    @memset(results, null);

    for (results) |*result| {
        var accepted = try server.accept(options);
        errdefer accepted.deinit(allocator);
        const task = ServeTask(HandlerContext){
            .accepted = accepted,
            .context = context,
            .handler = handler,
            .result = result,
            .allocator = allocator,
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

/// Run a long-lived bounded service over any MQTT pending source. Public
/// transport wrappers use this boundary so TCP, Unix, TLS, WS and WSS share
/// identical cancellation and error-isolation behavior.
pub fn serveSourceUntil(
    source: PendingSource,
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (
        *HandlerContext,
        *AcceptedClient,
    ) Error!void,
    max_connections: usize,
    accept_options: AcceptOptions,
    options: ServeUntilOptions,
) anyerror!void {
    if (max_connections == 0 or
        options.accept_error_backoff.nanoseconds < 0)
    {
        return error.InvalidProperty;
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
            ServeUntilTask(HandlerContext, handler).run,
            .{ServeUntilTask(HandlerContext, handler){
                .supervisor = &supervisor,
                .source = source,
                .context = context,
                .allocator = allocator,
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
    try select.concurrent(
        .shutdown,
        waitForServeEvent,
        .{ options.shutdown, io },
    );
    try select.concurrent(
        .failure,
        waitForServeEvent,
        .{ &supervisor.failed, io },
    );
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
    comptime HandlerContext: type,
    comptime handler: *const fn (
        *HandlerContext,
        *AcceptedClient,
    ) Error!void,
) type {
    return struct {
        supervisor: *ServeSupervisorState,
        source: PendingSource,
        context: *HandlerContext,
        allocator: std.mem.Allocator,
        accept_options: AcceptOptions,

        fn run(task: @This()) std.Io.Cancelable!void {
            while (!task.supervisor.shouldStop()) {
                var pending = task.source.acceptPending(
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
                var accepted = pending.finish(
                    task.accept_options,
                ) catch |err| {
                    pending.deinit(task.allocator);
                    if (err == error.Canceled and
                        task.supervisor.shouldStop()) return;
                    task.supervisor.report(.accept, err);
                    if (task.supervisor.shouldStop()) return;
                    continue;
                };
                defer accepted.deinit(task.allocator);
                handler(task.context, &accepted) catch |err| {
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
        accepted: AcceptedClient,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, *AcceptedClient) Error!void,
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

pub const AcceptOptions = struct {
    protocol: mqtt.ProtocolVersion = .v5,
    /// Protocol versions admitted after CONNECT auto-detection. The protocol
    /// field above remains only the initial parsing/encoding hint.
    accepted_protocol_versions: mqtt.AcceptedProtocolVersions = .{},
    /// Reject discouraged C0/C1 control characters in every UTF-8 Encoded
    /// String received from the client. The base wire codec always rejects
    /// MQTT-forbidden NUL and Unicode noncharacters; enable this stricter
    /// policy for Mosquitto-style broker admission.
    strict_utf8: bool = false,
    /// Optional process-wide wire counter sink. Every complete MQTT Control
    /// Packet is charged after a successful transport read or write, including
    /// CONNECT/CONNACK and packets later rejected by semantic validation.
    traffic_counters: ?*TrafficCounters = null,
    /// Retain live deltas on the Connection until an explicit flush or close.
    /// Broker owners that include active Connection snapshots can avoid a
    /// shared atomic update for every packet while preserving lifetime totals.
    traffic_counters_deferred: bool = false,
    /// Absolute budget for receiving the first complete CONNECT packet after
    /// the underlying TCP/TLS/WebSocket transport is established. A null value
    /// preserves unbounded behavior; zero fails before reading.
    connect_timeout: ?std.Io.Duration = null,
    v3_1_connack_mode: V31ConnAckMode = .strict,
    session_present: bool = false,
    reason_code: u8 = 0,
    assigned_client_identifier: ?[]const u8 = null,
    /// Optional MQTT 5 alternative authority. Redirecting clients consume it
    /// only with Use Another Server / Server Moved; other reason codes may use
    /// it as the protocol's informational hint.
    server_reference: ?[]const u8 = null,
    /// Optional response-prefix hint returned only when an MQTT 5 client asks
    /// for Response Information in CONNECT. The string is borrowed through
    /// synchronous CONNACK encoding and must be valid MQTT UTF-8.
    response_information: ?[]const u8 = null,
    /// Server-side outbound PUBLISH limit before CONNECT negotiation and the
    /// Receive Maximum advertised to clients. MQTT 3.1.1 cannot advertise the
    /// latter, but the same local inbound safety limit is still enforced.
    max_outgoing_inflight: u16 = 16,
    /// Local ceiling for Topic Aliases created in server-to-client PUBLISH
    /// packets. The effective limit is the smaller of this value and the
    /// Topic Alias Maximum supplied by the MQTT 5 client.
    max_outgoing_topic_aliases: u16 = std.math.maxInt(u16),
    /// Maximum Topic Alias accepted from the peer. Servers advertise non-zero
    /// values in CONNACK; zero disables aliases and omits the property.
    topic_alias_maximum: u16 = 16,
    server_keep_alive_seconds: ?u16 = null,
    /// Optional upper bound for the Keep Alive requested by CONNECT. MQTT 5
    /// negotiates violations down with Server Keep Alive; MQTT 3.1.1 must be
    /// refused because it has no equivalent response property.
    maximum_keep_alive_seconds: ?u16 = null,
    /// Whether clients may request an assigned identifier by sending an empty
    /// Client ID. MQTT 3.1.1 still requires CleanSession=1; MQTT 5 permits
    /// either Clean Start value.
    allow_zero_length_client_id: bool = true,
    maximum_qos: ?mqtt.QoS = null,
    retain_available: bool = true,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
};

/// A point-in-time MQTT Control Packet traffic snapshot. Byte counts cover the
/// complete MQTT packet, including its fixed header and Remaining Length bytes,
/// but deliberately exclude TCP, TLS, and WebSocket framing overhead.
pub const TrafficStats = struct {
    messages_received: u64,
    messages_sent: u64,
    bytes_received: u64,
    bytes_sent: u64,

    pub fn add(self: *TrafficStats, values: TrafficStats) void {
        self.messages_received +%= values.messages_received;
        self.messages_sent +%= values.messages_sent;
        self.bytes_received +%= values.bytes_received;
        self.bytes_sent +%= values.bytes_sent;
    }
};

/// Thread-safe cumulative counters suitable for sharing across all connections
/// of a broker. Connections retain their own counters as well, while attaching
/// a broker sink transfers the already accumulated prefix exactly once.
pub const TrafficCounters = struct {
    messages_received: std.atomic.Value(u64) = .init(0),
    messages_sent: std.atomic.Value(u64) = .init(0),
    bytes_received: std.atomic.Value(u64) = .init(0),
    bytes_sent: std.atomic.Value(u64) = .init(0),

    pub fn stats(self: *const TrafficCounters) TrafficStats {
        return .{
            .messages_received = self.messages_received.load(.monotonic),
            .messages_sent = self.messages_sent.load(.monotonic),
            .bytes_received = self.bytes_received.load(.monotonic),
            .bytes_sent = self.bytes_sent.load(.monotonic),
        };
    }

    pub fn add(self: *TrafficCounters, values: TrafficStats) void {
        _ = self.messages_received.fetchAdd(
            values.messages_received,
            .monotonic,
        );
        _ = self.messages_sent.fetchAdd(values.messages_sent, .monotonic);
        _ = self.bytes_received.fetchAdd(values.bytes_received, .monotonic);
        _ = self.bytes_sent.fetchAdd(values.bytes_sent, .monotonic);
    }

    pub fn recordReceived(self: *TrafficCounters, bytes: usize) void {
        _ = self.messages_received.fetchAdd(1, .monotonic);
        _ = self.bytes_received.fetchAdd(@intCast(bytes), .monotonic);
    }

    pub fn recordSent(self: *TrafficCounters, bytes: usize) void {
        _ = self.messages_sent.fetchAdd(1, .monotonic);
        _ = self.bytes_sent.fetchAdd(@intCast(bytes), .monotonic);
    }

    /// Update one connection-owned receive direction. Connection reads have a
    /// single protocol owner, while snapshots may load these values from
    /// another task; atomic load/store preserves that observation boundary
    /// without paying for a multi-writer read-modify-write operation.
    pub fn recordReceivedExclusive(self: *TrafficCounters, bytes: usize) void {
        self.messages_received.store(
            self.messages_received.load(.monotonic) +% 1,
            .monotonic,
        );
        self.bytes_received.store(
            self.bytes_received.load(.monotonic) +% @as(u64, @intCast(bytes)),
            .monotonic,
        );
    }

    /// Update one connection-owned send direction. Public Connections require
    /// one writer, and broker Connections enforce that ownership with their
    /// writer mutex. Aggregate sinks remain multi-writer and still use the
    /// `fetchAdd` path above.
    pub fn recordSentExclusive(self: *TrafficCounters, bytes: usize) void {
        self.messages_sent.store(
            self.messages_sent.load(.monotonic) +% 1,
            .monotonic,
        );
        self.bytes_sent.store(
            self.bytes_sent.load(.monotonic) +% @as(u64, @intCast(bytes)),
            .monotonic,
        );
    }
};

pub const AcceptedClient = struct {
    connection: Connection,
    connect: OwnedConnect,

    pub fn deinit(self: *AcceptedClient, allocator: std.mem.Allocator) void {
        self.connect.deinit(allocator);
        self.connection.close();
        self.* = undefined;
    }
};

/// An owned response prepared before a broker changes Session state. Encoded
/// bytes own all property data. Keep the pending client alive through deadline
/// validation and finishing; disposing the plan only releases its owned bytes.
/// Deinit can follow either abort or successful ownership transfer.
pub const PreparedAcceptance = struct {
    pending: *PendingAcceptedClient,
    connack: connack_preparation.Prepared,
    deadline: ?std.Io.Clock.Timestamp,
    reason_code: u8,
    session_present: bool,
    max_outgoing_topic_aliases: u16,
    consumed: bool = false,

    pub fn validateDeadline(self: *const PreparedAcceptance) Error!void {
        std.debug.assert(!self.consumed);
        if (earliestClockDeadline(self.deadline, self.pending.admission_deadline)) |absolute| {
            _ = try deadline_policy.usableAwake(self.pending.connection.transport.ioHandle(), absolute);
        }
    }

    pub fn deinit(self: *PreparedAcceptance) void {
        self.connack.deinit();
        self.* = undefined;
    }
};

/// Server-side CONNECT accepted at the packet/runtime layer but not yet
/// acknowledged.
///
/// Stateful brokers may prepare a response for prospective Session State,
/// commit admission, then call `finishPrepared`. The synchronous `finish`
/// convenience path preserves the same encoding and negotiation behavior.
pub const PendingAcceptedClient = struct {
    connection: Connection,
    connect: OwnedConnect,
    /// Preserve the wire-level Client ID state even if broker admission
    /// replaces the exposed identifier with its generated value.
    client_id_was_empty: bool = false,
    /// Effective deadline established while CONNECT was received. Two-phase
    /// admission keeps it so policy and authentication code cannot
    /// accidentally renew or discard the original budget.
    admission_deadline: ?std.Io.Clock.Timestamp = null,
    protocol_allowed: bool = true,
    authentication_authorized: bool = false,
    authentication_rejection_reason: ?u8 = null,
    authentication_data: ?[]u8 = null,

    /// Check the original CONNECT budget after caller policy work and before
    /// that caller starts stateful admission or further resource preparation.
    pub fn validateAdmissionDeadline(self: *const PendingAcceptedClient) Error!void {
        if (self.admission_deadline) |deadline| {
            _ = try deadline_policy.usableAwake(self.connection.transport.ioHandle(), deadline);
        }
    }

    pub fn finish(
        self: *PendingAcceptedClient,
        options: AcceptOptions,
    ) Error!AcceptedClient {
        return self.finishMaybeBefore(options, self.admission_deadline);
    }

    pub fn finishWithTimeout(
        self: *PendingAcceptedClient,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishWithDeadline(options, .fromNow(
            self.connection.transport.ioHandle(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn finishWithDeadline(
        self: *PendingAcceptedClient,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!AcceptedClient {
        _ = try deadline_policy.usableAwake(
            self.connection.transport.ioHandle(),
            deadline,
        );
        return self.finishMaybeBefore(
            options,
            earliestClockDeadline(self.admission_deadline, deadline),
        );
    }

    fn finishMaybeBefore(
        self: *PendingAcceptedClient,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!AcceptedClient {
        var prepared = try self.prepareFinishMaybeBefore(options, deadline);
        defer prepared.deinit();
        return self.finishPrepared(&prepared);
    }

    /// Build and validate CONNACK before a stateful owner's admission commit.
    /// Authentication and negotiated state remain unchanged until finish.
    pub fn prepareFinish(self: *PendingAcceptedClient, options: AcceptOptions) Error!PreparedAcceptance {
        return self.prepareFinishMaybeBefore(options, self.admission_deadline);
    }

    pub fn prepareFinishWithTimeout(self: *PendingAcceptedClient, options: AcceptOptions, timeout: std.Io.Duration) Error!PreparedAcceptance {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.prepareFinishWithDeadline(options, .fromNow(self.connection.transport.ioHandle(), .{ .raw = timeout, .clock = .awake }));
    }

    pub fn prepareFinishWithDeadline(
        self: *PendingAcceptedClient,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PreparedAcceptance {
        _ = try deadline_policy.usableAwake(self.connection.transport.ioHandle(), deadline);
        return self.prepareFinishMaybeBefore(options, earliestClockDeadline(self.admission_deadline, deadline));
    }

    fn prepareFinishMaybeBefore(
        self: *PendingAcceptedClient,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PreparedAcceptance {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connection.transport.ioHandle(), absolute);
        const resolved = try self.resolvedOptions(options);
        if (self.authentication_rejection_reason) |reason_code| {
            if (resolved.reason_code != reason_code) {
                return error.InvalidAuthenticationState;
            }
        }
        try validateAssignedClientIdentifierForConnect(
            self.connection.protocol,
            self.client_id_was_empty,
            resolved.reason_code == 0,
            resolved.assigned_client_identifier,
        );
        var properties: [5]mqtt.Property = undefined;
        var property_count: usize = 0;
        if (self.connection.protocol == .v5 and
            resolved.assigned_client_identifier != null)
        {
            properties[property_count] = .{ .utf8 = .{
                .id = .assigned_client_identifier,
                .value = resolved.assigned_client_identifier.?,
            } };
            property_count += 1;
        }
        if (self.connection.protocol == .v5 and
            resolved.reason_code == 0 and
            resolved.response_information != null and
            mqtt.requestResponseInformation(
                self.connect.connect.properties,
            ) == true)
        {
            properties[property_count] = .{ .utf8 = .{
                .id = .response_information,
                .value = resolved.response_information.?,
            } };
            property_count += 1;
        }
        if (resolved.reason_code == 0) {
            if (self.connection.authentication.method()) |method| {
                if (!self.authentication_authorized) {
                    return error.AuthenticationInProgress;
                }
                properties[property_count] = .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } };
                property_count += 1;
            }
            if (self.authentication_data) |data| {
                properties[property_count] = .{ .binary = .{
                    .id = .authentication_data,
                    .value = data,
                } };
                property_count += 1;
            }
        }
        if (resolved.server_reference) |reference| {
            properties[property_count] = .{ .utf8 = .{
                .id = .server_reference,
                .value = reference,
            } };
            property_count += 1;
        }
        const connack_options: ConnAckOptions = .{
            .v3_1_connack_mode = resolved.v3_1_connack_mode,
            .session_present = if (self.connection.protocol == .v3_1 and
                resolved.v3_1_connack_mode == .strict)
                false
            else
                resolved.session_present,
            .reason_code = resolved.reason_code,
            .properties = properties[0..property_count],
            .max_outgoing_inflight = resolved.max_outgoing_inflight,
            .topic_alias_maximum = resolved.topic_alias_maximum,
            .server_keep_alive_seconds = resolved.server_keep_alive_seconds,
            .maximum_qos = resolved.maximum_qos,
            .retain_available = resolved.retain_available,
            .wildcard_subscription_available = resolved.wildcard_subscription_available,
            .subscription_identifier_available = resolved.subscription_identifier_available,
            .shared_subscription_available = resolved.shared_subscription_available,
        };
        var connack = try self.connection.prepareConnAck(connack_options);
        errdefer connack.deinit();
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connection.transport.ioHandle(), absolute);
        return .{
            .pending = self,
            .connack = connack,
            .deadline = deadline,
            .reason_code = resolved.reason_code,
            .session_present = resolved.session_present,
            .max_outgoing_topic_aliases = resolved.max_outgoing_topic_aliases,
        };
    }

    /// Send a previously prepared response under its original deadline, then
    /// move the accepted connection and CONNECT to their new owner. The plan
    /// must belong to this pending client; deinit remains valid after finish.
    pub fn finishPrepared(self: *PendingAcceptedClient, prepared: *PreparedAcceptance) Error!AcceptedClient {
        std.debug.assert(prepared.pending == self and !prepared.consumed);
        try prepared.validateDeadline();
        const deadline = earliestClockDeadline(self.admission_deadline, prepared.deadline);
        try self.connection.writePreparedConnAckMaybeBefore(&prepared.connack, deadline);
        self.connection.peer_topic_alias_maximum = @min(self.connection.peer_topic_alias_maximum, prepared.max_outgoing_topic_aliases);
        if (prepared.reason_code == 0 and self.connection.authentication.phase == .authenticating) {
            try self.connection.authentication.finishServerInitial();
        }
        if (self.authentication_data) |data| {
            self.connection.allocator.free(data);
            self.authentication_data = null;
        }
        prepared.consumed = true;
        const accepted = AcceptedClient{ .connection = self.connection, .connect = self.connect };
        self.* = undefined;
        return accepted;
    }

    /// Resolve CONNECT-dependent acceptance policy without mutating state.
    /// Stateful brokers call this before registration so a refused client can
    /// never create Session, Will, or router records; direct TCP/TLS/WS/WSS
    /// servers get the same behavior automatically through `finish`.
    pub fn resolvedOptions(
        self: PendingAcceptedClient,
        options: AcceptOptions,
    ) Error!AcceptOptions {
        var resolved = options;
        if (resolved.max_outgoing_inflight == 0 or
            resolved.maximum_keep_alive_seconds == 0 or
            !resolved.accepted_protocol_versions.any())
        {
            return error.InvalidProperty;
        }
        const connect = self.connect.connect;
        if (connect.clean_start) {
            // A clean start discards any prior Session, so MQTT 3.1/3.1.1/5
            // both require the successful CONNACK's Session Present bit to be
            // zero regardless of a direct server caller's requested value.
            resolved.session_present = false;
        }
        if (!self.protocol_allowed or
            !resolved.accepted_protocol_versions.allows(connect.protocol))
        {
            resolved.reason_code = switch (connect.protocol) {
                .v3_1, .v3_1_1 => 0x01,
                .v5 => 0x84,
            };
            resolved.session_present = false;
            resolved.assigned_client_identifier = null;
            resolved.response_information = null;
            resolved.server_keep_alive_seconds = null;
            return resolved;
        }
        if (resolved.reason_code != 0) {
            // Refused connections cannot carry successful-negotiation state.
            // Normalizing here also prevents a caller-supplied Session Present
            // bit or capability setting from producing an invalid CONNACK.
            resolved.session_present = false;
            resolved.assigned_client_identifier = null;
            resolved.response_information = null;
            resolved.server_keep_alive_seconds = null;
            return resolved;
        }
        const maximum_qos = resolved.maximum_qos orelse .exactly_once;
        if (connect.will) |will| {
            if (@intFromEnum(will.qos) > @intFromEnum(maximum_qos)) {
                resolved.reason_code = switch (connect.protocol) {
                    .v3_1, .v3_1_1 => 0x05,
                    .v5 => 0x9b,
                };
                resolved.session_present = false;
                resolved.assigned_client_identifier = null;
                resolved.response_information = null;
                resolved.server_keep_alive_seconds = null;
                return resolved;
            }
        }
        if (connect.client_id.len == 0 and
            !resolved.allow_zero_length_client_id)
        {
            resolved.reason_code = switch (connect.protocol) {
                .v3_1, .v3_1_1 => 0x02,
                .v5 => 0x80,
            };
            resolved.session_present = false;
            resolved.assigned_client_identifier = null;
            resolved.response_information = null;
            resolved.server_keep_alive_seconds = null;
            return resolved;
        }
        if (resolved.maximum_keep_alive_seconds) |maximum| {
            if (resolved.server_keep_alive_seconds) |explicit| {
                resolved.server_keep_alive_seconds = @min(
                    explicit,
                    maximum,
                );
            }
            if (connect.keep_alive_seconds == 0 or
                connect.keep_alive_seconds > maximum)
            {
                switch (connect.protocol) {
                    .v3_1, .v3_1_1 => {
                        resolved.reason_code = 0x02;
                        resolved.session_present = false;
                        resolved.assigned_client_identifier = null;
                        resolved.response_information = null;
                        resolved.server_keep_alive_seconds = null;
                    },
                    .v5 => resolved.server_keep_alive_seconds = if (resolved.server_keep_alive_seconds) |explicit|
                        @min(explicit, maximum)
                    else
                        maximum,
                }
            }
        }
        return resolved;
    }

    /// Send one pre-CONNACK Enhanced Authentication challenge.
    pub fn challengeAuthentication(
        self: *PendingAcceptedClient,
        data: []const u8,
    ) Error!void {
        return self.challengeAuthenticationMaybeBefore(
            data,
            self.admission_deadline,
        );
    }

    pub fn challengeAuthenticationWithTimeout(
        self: *PendingAcceptedClient,
        data: []const u8,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.challengeAuthenticationWithDeadline(data, .fromNow(
            self.connection.transport.ioHandle(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn challengeAuthenticationWithDeadline(
        self: *PendingAcceptedClient,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        _ = try deadline_policy.usableAwake(
            self.connection.transport.ioHandle(),
            deadline,
        );
        return self.challengeAuthenticationMaybeBefore(
            data,
            earliestClockDeadline(self.admission_deadline, deadline),
        );
    }

    fn challengeAuthenticationMaybeBefore(
        self: *PendingAcceptedClient,
        data: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        const method = self.connection.authentication.method() orelse
            return error.AuthenticationNotConfigured;
        const properties = [_]mqtt.Property{
            .{ .utf8 = .{
                .id = .authentication_method,
                .value = method,
            } },
            .{ .binary = .{
                .id = .authentication_data,
                .value = data,
            } },
        };
        if (deadline) |absolute|
            try self.connection.writeAuthWithDeadline(
                0x18,
                &properties,
                absolute,
            )
        else
            try self.connection.writeAuth(0x18, &properties);
    }

    /// Receive and validate one client Continue Authentication packet.
    pub fn receiveAuthentication(
        self: *PendingAcceptedClient,
    ) Error!OwnedAuth {
        return self.receiveAuthenticationMaybeBefore(
            self.admission_deadline,
        );
    }

    pub fn receiveAuthenticationWithTimeout(
        self: *PendingAcceptedClient,
        timeout: std.Io.Duration,
    ) Error!OwnedAuth {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveAuthenticationWithDeadline(.fromNow(
            self.connection.transport.ioHandle(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveAuthenticationWithDeadline(
        self: *PendingAcceptedClient,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedAuth {
        _ = try deadline_policy.usableAwake(
            self.connection.transport.ioHandle(),
            deadline,
        );
        return self.receiveAuthenticationMaybeBefore(
            earliestClockDeadline(self.admission_deadline, deadline),
        );
    }

    fn receiveAuthenticationMaybeBefore(
        self: *PendingAcceptedClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedAuth {
        var auth = if (deadline) |absolute|
            try self.connection.readAuthWithDeadline(absolute)
        else
            try self.connection.readAuth();
        errdefer auth.deinit(self.connection.allocator);
        try self.connection.authentication.receiveInitialAuth(
            auth.auth,
        );
        return auth;
    }

    /// Commit application approval before sending the successful CONNACK.
    pub fn authorizeAuthentication(
        self: *PendingAcceptedClient,
    ) Error!void {
        try self.authorizeAuthenticationWithData(null);
    }

    /// Commit approval and attach optional final Authentication Data to
    /// CONNACK. The bytes are copied because broker policies may return before
    /// Session setup and CONNACK emission complete.
    pub fn authorizeAuthenticationWithData(
        self: *PendingAcceptedClient,
        data: ?[]const u8,
    ) Error!void {
        if (self.connection.authentication.phase != .authenticating or
            self.authentication_rejection_reason != null)
        {
            return error.InvalidAuthenticationState;
        }
        const owned = if (data) |value|
            try self.connection.allocator.dupe(u8, value)
        else
            null;
        if (self.authentication_data) |old| {
            self.connection.allocator.free(old);
        }
        self.authentication_data = owned;
        self.authentication_authorized = true;
    }

    /// Stage a failed Enhanced Authentication decision for a stateful Broker.
    /// The Broker sends a property-free failure CONNACK before discarding the
    /// provisional connection, so no Session, Will, or routing state becomes
    /// visible. A policy must choose either authorization or rejection once.
    pub fn rejectAuthentication(
        self: *PendingAcceptedClient,
        reason_code: u8,
    ) Error!void {
        if (self.connection.authentication.phase != .authenticating or
            self.authentication_authorized or
            self.authentication_rejection_reason != null or
            reason_code == 0)
        {
            return error.InvalidAuthenticationState;
        }
        try mqtt.validateConnAckReason(.v5, reason_code);
        self.authentication_rejection_reason = reason_code;
    }

    /// Return the policy-staged failure reason, if authentication was rejected.
    pub fn authenticationRejectionReason(
        self: *const PendingAcceptedClient,
    ) ?u8 {
        return self.authentication_rejection_reason;
    }

    /// Replace the wire username with a deep-owned identity established by
    /// the authentication mechanism. The password is cleared, and the
    /// identity becomes immutable once the policy authorizes or rejects the
    /// connection.
    pub fn setAuthenticatedUsername(
        self: *PendingAcceptedClient,
        username: []const u8,
    ) Error!void {
        if (self.connection.authentication.phase != .authenticating or
            self.authentication_authorized or
            self.authentication_rejection_reason != null)
        {
            return error.InvalidAuthenticationState;
        }
        try self.connect.replaceUsername(
            self.connection.allocator,
            username,
        );
    }

    pub fn deinit(
        self: *PendingAcceptedClient,
        allocator: std.mem.Allocator,
    ) void {
        if (self.authentication_data) |data| allocator.free(data);
        self.connect.deinit(allocator);
        self.connection.close();
        self.* = undefined;
    }
};

pub const Client = struct {
    /// Negotiate MQTT on a caller-connected TCP stream. Ownership transfers to
    /// this call on every outcome, enabling reusable proxy/tunnel adapters
    /// without duplicating MQTT CONNECT state.
    pub fn connectStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        return connectOwnedStreamAttempt(
            allocator,
            io,
            stream,
            options,
            true,
        );
    }

    pub fn connectStreamAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        return connectOwnedStreamAttemptBefore(
            allocator,
            io,
            stream,
            options,
            true,
            deadline,
        );
    }

    pub fn connectStreamAttemptWithTimeout(
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
        return connectStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, options: ConnectOptions) Error!Connection {
        var result = try connectWithConnAck(allocator, io, address, options);
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectWithConnAck(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, options: ConnectOptions) Error!ConnectResult {
        var attempt = try connectAttempt(allocator, io, address, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
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

    /// Like `connectWithDeadline`, but preserves the accepted CONNACK. The
    /// caller-owned awake-clock deadline covers TCP setup and all MQTT
    /// negotiation; `network_connect_timeout` and `connect_timeout` remain
    /// independent upper bounds for their respective phases.
    pub fn connectWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectResult {
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
    ) Error!ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithConnAckWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAttempt(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, options: ConnectOptions) Error!ConnectAttempt {
        const stream = try tcp_connect.ip(
            io,
            address,
            options.network_connect_timeout,
        );
        return connectOwnedStreamAttempt(allocator, io, stream, options, true);
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const network_deadline = try cappedConnectDeadline(
            io,
            deadline,
            options.network_connect_timeout,
        );
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            network_deadline,
        );
        return connectOwnedStreamAttemptBefore(
            allocator,
            io,
            stream,
            options,
            true,
            deadline,
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

    /// Resolve a DNS hostname and establish a cleartext MQTT connection. DNS
    /// lookup and every TCP address attempt share `network_connect_timeout`.
    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) Error!Connection {
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
    ) Error!ConnectResult {
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
    ) Error!ConnectAttempt {
        const stream = try network_endpoint.connectHost(
            allocator,
            io,
            host,
            port,
            options.network_connect_timeout,
            options.address_resolver,
            options.address_connect_policy,
        );
        return connectOwnedStreamAttempt(allocator, io, stream, options, true);
    }

    /// Resolve a hostname and connect from one explicit local IP address.
    /// Zig 0.16 does not expose bound connects through generic `std.Io`, so
    /// this operation currently requires netz's zio runtime backend.
    pub fn connectHostAttemptBound(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        local_address: net.IpAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        const stream = try network_endpoint.connectHostBound(
            allocator,
            io,
            host,
            port,
            local_address,
            options.network_connect_timeout,
            options.address_resolver,
            options.address_connect_policy,
        );
        return connectOwnedStreamAttempt(allocator, io, stream, options, true);
    }

    /// Resolve `host` and negotiate MQTT under one caller-owned deadline.
    /// DNS and all address attempts also retain `network_connect_timeout` as
    /// a stricter phase limit when it expires first.
    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const network_deadline = try cappedConnectDeadline(
            io,
            deadline,
            options.network_connect_timeout,
        );
        const stream = try network_endpoint.connectHostWithDeadline(
            allocator,
            io,
            host,
            port,
            network_deadline,
            options.address_resolver,
            options.address_connect_policy,
        );
        return connectOwnedStreamAttemptBefore(
            allocator,
            io,
            stream,
            options,
            true,
            deadline,
        );
    }

    pub fn connectHostAttemptBoundWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        local_address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const network_deadline = try cappedConnectDeadline(
            io,
            deadline,
            options.network_connect_timeout,
        );
        const stream = try network_endpoint.connectHostBoundWithDeadline(
            allocator,
            io,
            host,
            port,
            local_address,
            network_deadline,
            options.address_resolver,
            options.address_connect_policy,
        );
        return connectOwnedStreamAttemptBefore(
            allocator,
            io,
            stream,
            options,
            true,
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

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
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

    pub fn connectHostWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectResult {
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
    ) Error!ConnectResult {
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

    /// Connect to a cleartext `mqtt://` or `tcp://` URI. Credentials, query,
    /// fragment, and non-empty paths are rejected by the shared MQTT target
    /// parser before any network operation begins.
    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!Connection {
        var result = try connectUriWithConnAck(
            allocator,
            io,
            uri_text,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!ConnectResult {
        var attempt = try connectUriAttempt(
            allocator,
            io,
            uri_text,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        var target = try redirect.parse(allocator, uri_text, .tcp);
        defer target.deinit();
        return connectTargetAttempt(allocator, io, target, options);
    }

    /// Connect and finish MQTT negotiation under one absolute deadline shared
    /// by DNS resolution, every TCP attempt, CONNECT, AUTH, and final CONNACK.
    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var target = try redirect.parse(allocator, uri_text, .tcp);
        defer target.deinit();
        const network_deadline = try cappedConnectDeadline(
            io,
            deadline,
            options.network_connect_timeout,
        );
        const stream = try network_endpoint.connectTargetWithDeadline(
            allocator,
            io,
            &target,
            .tcp,
            network_deadline,
            options.address_resolver,
            options.address_connect_policy,
        );
        return connectOwnedStreamAttemptBefore(
            allocator,
            io,
            stream,
            options,
            true,
            deadline,
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

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var result = try connectUriWithConnAckWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
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

    pub fn connectUriWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectResult {
        var attempt = try connectUriAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithConnAckWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) Error!Connection {
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
    ) Error!ConnectResult {
        var attempt = try connectUnixAttempt(allocator, io, address, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
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

    pub fn connectUnixWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectResult {
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
    ) Error!ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithConnAckWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUnixAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.limits.tcp_keepalive != null or
            options.limits.tcp_user_timeout_ms != null)
        {
            return error.SocketOptionUnsupported;
        }
        const stream = try tcp_connect.unix(
            io,
            address,
            options.network_connect_timeout,
        );
        return connectOwnedStreamAttempt(allocator, io, stream, options, false);
    }

    /// Connect a Unix socket and negotiate MQTT under one caller-owned
    /// awake-clock deadline, retaining stricter configured phase limits.
    pub fn connectUnixAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.limits.tcp_keepalive != null or
            options.limits.tcp_user_timeout_ms != null)
        {
            return error.SocketOptionUnsupported;
        }
        const network_deadline = try cappedConnectDeadline(
            io,
            deadline,
            options.network_connect_timeout,
        );
        const stream = try tcp_connect.unixWithDeadline(
            io,
            address,
            network_deadline,
        );
        return connectOwnedStreamAttemptBefore(
            allocator,
            io,
            stream,
            options,
            false,
            deadline,
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

    /// Follow MQTT 5 redirect CONNACKs for cleartext TCP.
    ///
    /// Redirects are disabled unless policy.max_redirects is non-zero. This
    /// URI form provides a stable authority string for loop detection.
    pub fn connectUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        policy: redirect.Policy,
    ) Error!ConnectResult {
        if (options.protocol != .v5) return error.UnsupportedRedirectScheme;
        var chain = redirect.Chain.init(allocator, policy);
        defer chain.deinit();
        var current_uri = try allocator.dupe(u8, uri_text);
        defer allocator.free(current_uri);
        try chain.recordInitial(current_uri, .tcp);

        while (true) {
            var target = try redirect.parse(allocator, current_uri, .tcp);
            defer target.deinit();
            var attempt = try connectTargetAttempt(
                allocator,
                io,
                target,
                options,
            );
            errdefer attempt.deinit(allocator);
            if (attempt.accepted()) return attempt.requireAccepted();
            const reference = (try redirect.referenceForConnAck(
                attempt.connack.connack,
            )) orelse return error.ConnectRefused;
            var next = try chain.follow(
                current_uri,
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
};

fn connectTargetAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: redirect.Target,
    options: ConnectOptions,
) Error!ConnectAttempt {
    const stream = try network_endpoint.connectTarget(
        allocator,
        io,
        &target,
        .tcp,
        options.network_connect_timeout,
        options.address_resolver,
        options.address_connect_policy,
    );
    return connectOwnedStreamAttempt(allocator, io, stream, options, true);
}

fn connectOwnedStreamAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: ConnectOptions,
    tcp_nodelay_available: bool,
) Error!ConnectAttempt {
    return connectOwnedStreamAttemptBefore(
        allocator,
        io,
        stream,
        options,
        tcp_nodelay_available,
        null,
    );
}

fn connectOwnedStreamAttemptBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: ConnectOptions,
    tcp_nodelay_available: bool,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ConnectAttempt {
    var stream_owned = true;
    errdefer if (stream_owned) stream.close(io);
    var limits = options.limits;
    if (!tcp_nodelay_available and
        (limits.tcp_keepalive != null or
            limits.tcp_user_timeout_ms != null))
    {
        return error.SocketOptionUnsupported;
    }
    limits.tcp_nodelay = tcp_nodelay_available and limits.tcp_nodelay;
    try socket_options.applyTcp(stream, .{
        .no_delay = limits.tcp_nodelay,
        .keep_alive = limits.tcp_keepalive,
        .user_timeout_ms = limits.tcp_user_timeout_ms,
    });

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
        .protocol = options.protocol,
        .limits = .from(limits),
        .proxy_v2_require_client_certificate = limits.proxy_v2_require_client_certificate,
        .max_outgoing_inflight = options.max_outgoing_inflight,
        .max_incoming_inflight = options.effectiveReceiveMaximum(),
        .incoming_topic_alias_maximum = options.topic_alias_maximum,
        .capabilities = .{
            .peer_maximum_qos = options.peer_maximum_qos,
            .peer_retain_available = options.peer_retain_available,
        },
    };
    stream_owned = false;
    errdefer connection.close();
    return if (deadline) |absolute|
        connection.establishClientWithDeadline(options, absolute)
    else
        connection.establishClient(options);
}

pub const ConnectAttempt = struct {
    connection: ?Connection,
    connack: OwnedConnAck,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.connection != null and self.connack.connack.reason_code == 0;
    }

    pub fn deinit(self: *ConnectAttempt, allocator: std.mem.Allocator) void {
        self.connack.deinit(allocator);
        if (self.connection) |*connection| connection.close();
        self.* = undefined;
    }

    pub fn requireAccepted(self: *ConnectAttempt) Error!ConnectResult {
        const connection = self.connection orelse return error.ConnectRefused;
        const connack = self.connack;
        self.connack = undefined;
        self.connection = null;
        return .{ .connection = connection, .connack = connack };
    }
};

pub const ConnectResult = struct {
    connection: Connection,
    connack: OwnedConnAck,

    pub fn deinit(self: *ConnectResult, allocator: std.mem.Allocator) void {
        self.connack.deinit(allocator);
        self.connection.close();
        self.* = undefined;
    }
};

pub const ConnectOptions = struct {
    protocol: mqtt.ProtocolVersion = .v5,
    client_id: []const u8,
    /// Emit Mosquitto's private bridge marker for MQTT 3.1/3.1.1;
    /// configured one-way reconnectors may retry without it after refusal.
    bridge_mode: bool = false,
    /// Interpret Mosquitto's non-standard MQTT 3.1 CONNACK bit 0 as Session
    /// Present. Strict mode follows the original specification and ignores it.
    v3_1_connack_mode: V31ConnAckMode = .strict,
    /// Reject discouraged C0/C1 control characters in every UTF-8 Encoded
    /// String received from the broker. The base wire codec always rejects
    /// MQTT-forbidden NUL and Unicode noncharacters.
    strict_utf8: bool = false,
    /// Absolute receive budget from the transmitted CONNECT through the final
    /// CONNACK. Interim Enhanced Authentication packets do not renew it.
    connect_timeout: ?std.Io.Duration = null,
    /// Absolute budget for opening the underlying network transport. MQTT's
    /// CONNECT/CONNACK exchange keeps the independent `connect_timeout` above.
    network_connect_timeout: ?std.Io.Duration = null,
    /// Optional resolver shared by TCP/TLS/WebSocket hostname and URI connects,
    /// redirects, and reconnect attempts. Literal IP targets bypass it.
    /// Returned addresses affect only network routing; authority and TLS
    /// identity stay bound to the configured host. The resolver context is
    /// borrowed and must outlive any reconnect client initialized from this
    /// options value.
    address_resolver: ?AddressResolver = null,
    /// Explicit multi-address TCP policy. Ordered fallback remains the default;
    /// Happy Eyeballs is opt-in and bounded by its configured stagger/parallel
    /// limits.
    address_connect_policy: AddressConnectPolicy = .ordered,
    clean_start: bool = true,
    keep_alive_seconds: u16 = 30,
    /// Baseline broker publish capabilities to enforce when MQTT 5 CONNACK
    /// omits the corresponding Maximum QoS / Retain Available properties.
    /// Explicit CONNACK properties still take precedence after negotiation.
    peer_maximum_qos: mqtt.QoS = .exactly_once,
    peer_retain_available: bool = true,
    properties: []const mqtt.Property = &.{},
    will: ?mqtt.LastWill = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    limits: Limits = .{},
    /// Local upper bound for complete MQTT packets sent to the peer. The
    /// effective limit is the smaller of this value and an MQTT 5 CONNACK
    /// Maximum Packet Size. `maxInt(usize)` is unlimited.
    max_outgoing_packet_size: usize = std.math.maxInt(usize),
    max_outgoing_inflight: u16 = 16,
    /// MQTT 5 Receive Maximum advertised to the broker. Null preserves the
    /// historical behavior of using `max_outgoing_inflight` for both sides.
    receive_maximum: ?u16 = null,
    topic_alias_maximum: u16 = 16,
    /// Local ceiling for Topic Aliases used toward the broker. The effective
    /// limit is also bounded by the peer's CONNACK value.
    max_outgoing_topic_aliases: u16 = std.math.maxInt(u16),
    /// Hard local policy for RETAIN on client-originated PUBLISH packets.
    outgoing_retain: bool = true,
    /// Required when CONNECT requests MQTT 5 Enhanced Authentication and the
    /// broker may send one or more AUTH challenges before CONNACK.
    authentication: ?ClientAuthHandler = null,

    pub fn effectiveReceiveMaximum(self: ConnectOptions) u16 {
        return mqtt.receiveMaximum(self.properties) orelse
            self.receive_maximum orelse
            self.max_outgoing_inflight;
    }
};

/// One client step for initial MQTT 5 enhanced authentication.
///
/// The callback receives the broker AUTH packet and returns properties for a
/// client Continue Authentication response. Returned slices must remain valid
/// until the runtime synchronously validates and encodes that response; they
/// may be reused when `respond` is called again or connect returns.
pub const ClientAuthHandler = struct {
    context: *anyopaque,
    respond: *const fn (
        context: *anyopaque,
        challenge: mqtt.Auth,
    ) Error![]const mqtt.Property,
};

/// Borrowed TLS resumption inputs for one reconnect attempt. A connector may
/// apply both so a highest-version client can resume with either server
/// version without discarding the other protocol's cached state.
pub const ClientTlsSessionTickets = struct {
    tls12: ?*const tls_stream.Tls12SessionTicket = null,
    tls13: ?*const tls_stream.Tls13SessionTicket = null,

    pub fn any(self: ClientTlsSessionTickets) bool {
        return self.tls12 != null or self.tls13 != null;
    }
};

/// Type-erased transport opener for reconnecting MQTT clients. The connector
/// owns only transport policy; the caller supplies the reconnect client's
/// deeply-owned MQTT CONNECT options on every attempt. Its context must
/// outlive every Client that borrows this value.
pub const ClientConnector = struct {
    context: *anyopaque,
    connect_attempt: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
    ) Error!ConnectAttempt,
    /// Optional absolute-budget variant. Reconnect clients use it to ensure
    /// `connectWithDeadline` and the initial branch of `pollWithDeadline` do
    /// not hide an unbounded transport/TLS attempt behind a bounded API.
    connect_attempt_deadline: ?*const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt = null,
    /// Optional transport hook used by the reconnecting client to carry an
    /// owned RFC 5077 ticket across successive TLS 1.2 Network Connections.
    /// Connectors for non-TLS transports may omit it and retain the ordinary
    /// `connect_attempt` path.
    connect_attempt_with_tls12_ticket: ?*const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        ticket: *const tls_stream.Tls12SessionTicket,
    ) Error!ConnectAttempt = null,
    connect_attempt_with_tls12_ticket_deadline: ?*const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        ticket: *const tls_stream.Tls12SessionTicket,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt = null,
    /// Preferred hook for version-flexible TLS connectors. Legacy connectors
    /// may keep implementing only the TLS 1.2 hook above.
    connect_attempt_with_tls_tickets: ?*const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        tickets: ClientTlsSessionTickets,
    ) Error!ConnectAttempt = null,
    connect_attempt_with_tls_tickets_deadline: ?*const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        tickets: ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt = null,

    pub fn connectAttempt(
        self: ClientConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        return self.connect_attempt(
            self.context,
            allocator,
            io,
            options,
        );
    }

    pub fn connectAttemptWithDeadline(
        self: ClientConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        const connect = self.connect_attempt_deadline orelse
            return error.ConnectorDeadlineUnsupported;
        return connect(self.context, allocator, io, options, deadline);
    }

    pub fn connectAttemptWithTls12Ticket(
        self: ClientConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        ticket: *const tls_stream.Tls12SessionTicket,
    ) Error!ConnectAttempt {
        if (self.connect_attempt_with_tls12_ticket) |connect| {
            return connect(self.context, allocator, io, options, ticket);
        }
        if (self.connect_attempt_with_tls_tickets) |connect| {
            return connect(
                self.context,
                allocator,
                io,
                options,
                .{ .tls12 = ticket },
            );
        }
        return self.connectAttempt(allocator, io, options);
    }

    pub fn connectAttemptWithTls12TicketAndDeadline(
        self: ClientConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        ticket: *const tls_stream.Tls12SessionTicket,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        if (self.connect_attempt_with_tls12_ticket_deadline) |connect| {
            return connect(
                self.context,
                allocator,
                io,
                options,
                ticket,
                deadline,
            );
        }
        if (self.connect_attempt_with_tls_tickets_deadline) |connect| {
            return connect(
                self.context,
                allocator,
                io,
                options,
                .{ .tls12 = ticket },
                deadline,
            );
        }
        return self.connectAttemptWithDeadline(
            allocator,
            io,
            options,
            deadline,
        );
    }

    pub fn connectAttemptWithTlsTickets(
        self: ClientConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        tickets: ClientTlsSessionTickets,
    ) Error!ConnectAttempt {
        if (!tickets.any()) return self.connectAttempt(allocator, io, options);
        if (self.connect_attempt_with_tls_tickets) |connect| {
            return connect(self.context, allocator, io, options, tickets);
        }
        if (tickets.tls12) |ticket| {
            return self.connectAttemptWithTls12Ticket(
                allocator,
                io,
                options,
                ticket,
            );
        }
        return self.connectAttempt(allocator, io, options);
    }

    pub fn connectAttemptWithTlsTicketsAndDeadline(
        self: ClientConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: ConnectOptions,
        tickets: ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        if (!tickets.any()) {
            return self.connectAttemptWithDeadline(
                allocator,
                io,
                options,
                deadline,
            );
        }
        if (self.connect_attempt_with_tls_tickets_deadline) |connect| {
            return connect(
                self.context,
                allocator,
                io,
                options,
                tickets,
                deadline,
            );
        }
        if (tickets.tls12) |ticket| {
            return self.connectAttemptWithTls12TicketAndDeadline(
                allocator,
                io,
                options,
                ticket,
                deadline,
            );
        }
        return self.connectAttemptWithDeadline(
            allocator,
            io,
            options,
            deadline,
        );
    }
};

pub fn applyConnAckNegotiation(
    connection: *Connection,
    connack: mqtt.ConnAck,
    options: ConnectOptions,
) void {
    connection.session_expiry_interval = if (connection.protocol == .v5)
        mqtt.sessionExpiryInterval(connack.properties) orelse mqtt.sessionExpiryInterval(options.properties) orelse 0
    else if (options.clean_start) 0 else std.math.maxInt(u32);
    if (mqtt.receiveMaximum(connack.properties)) |receive_maximum| {
        connection.max_outgoing_inflight = negotiatedOutgoingInflightLimit(
            connection.max_outgoing_inflight,
            receive_maximum,
        );
    }
    const peer_max_packet_size: usize = if (mqtt.maximumPacketSize(
        connack.properties,
    )) |maximum_packet_size|
        maximum_packet_size
    else
        std.math.maxInt(usize);
    connection.peer_max_packet_size = @min(
        options.max_outgoing_packet_size,
        peer_max_packet_size,
    );
    if (mqtt.topicAliasMaximum(connack.properties)) |topic_alias_maximum| {
        connection.peer_topic_alias_maximum = @min(
            topic_alias_maximum,
            options.max_outgoing_topic_aliases,
        );
    }
    if (mqtt.serverKeepAlive(connack.properties)) |server_keep_alive| {
        connection.keep_alive_seconds = server_keep_alive;
    }
    if (mqtt.maximumQoS(connack.properties)) |maximum_qos| {
        connection.capabilities.peer_maximum_qos = maximum_qos;
    }
    if (mqtt.retainAvailable(connack.properties)) |retain_available| {
        connection.capabilities.peer_retain_available = retain_available;
    }
    connection.capabilities.outgoing_retain_enabled = options.outgoing_retain;
    if (mqtt.wildcardSubscriptionAvailable(connack.properties)) |available| {
        connection.capabilities.peer_wildcard_subscription_available = available;
    }
    if (mqtt.subscriptionIdentifierAvailable(connack.properties)) |available| {
        connection.capabilities.peer_subscription_identifier_available = available;
    }
    if (mqtt.sharedSubscriptionAvailable(connack.properties)) |available| {
        connection.capabilities.peer_shared_subscription_available = available;
    }
}

pub fn validateAssignedClientIdentifierForConnect(
    protocol: mqtt.ProtocolVersion,
    requested_empty_client_id: bool,
    accepted: bool,
    assigned_client_id: ?[]const u8,
) Error!void {
    if (protocol != .v5) return;
    if (!accepted) {
        if (assigned_client_id != null) return error.InvalidProperty;
        return;
    }
    if (requested_empty_client_id) {
        if (assigned_client_id == null or assigned_client_id.?.len == 0) {
            return error.InvalidProperty;
        }
    } else if (assigned_client_id != null) {
        return error.InvalidProperty;
    }
}

pub const ConnAckOptions = struct {
    v3_1_connack_mode: V31ConnAckMode = .strict,
    session_present: bool = false,
    reason_code: u8 = 0,
    properties: []const mqtt.Property = &.{},
    max_outgoing_inflight: u16 = 16,
    topic_alias_maximum: u16 = 16,
    server_keep_alive_seconds: ?u16 = null,
    maximum_qos: ?mqtt.QoS = null,
    retain_available: bool = true,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
};

pub fn negotiatedOutgoingInflightLimit(local_upper_limit: u16, peer_receive_maximum: u16) u16 {
    // MQTT 5 Receive Maximum is the peer's limit for QoS 1/2 PUBLISH packets
    // that we may have in flight.  Like rumqtt, keep the configured local
    // upper bound as a hard ceiling so a peer cannot enlarge local queue/window
    // state by advertising a larger value in CONNECT/CONNACK.
    return @min(local_upper_limit, peer_receive_maximum);
}

pub fn earliestClockDeadline(
    a: ?std.Io.Clock.Timestamp,
    b: ?std.Io.Clock.Timestamp,
) ?std.Io.Clock.Timestamp {
    const left = a orelse return b;
    const right = b orelse return left;
    return if (std.Io.Clock.Timestamp.compare(left, .lt, right))
        left
    else
        right;
}

fn cappedConnectDeadline(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    timeout: ?std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    return deadline_policy.capTimeout(io, deadline, timeout);
}

pub fn appendTopicAliasMaximumSetting(
    properties: *std.ArrayList(mqtt.Property),
    allocator: std.mem.Allocator,
    explicit_properties: []const mqtt.Property,
    configured_maximum: u16,
) Error!void {
    if (configured_maximum != 0 and
        mqtt.topicAliasMaximum(explicit_properties) == null)
    {
        const property: mqtt.Property = .{
            .two_byte = .{
                .id = .topic_alias_maximum,
                .value = configured_maximum,
            },
        };
        if (properties.items.len < properties.capacity) {
            properties.appendAssumeCapacity(property);
        } else {
            try properties.append(allocator, property);
        }
    }
}

pub fn problemInformationProperty(property: mqtt.Property) bool {
    return switch (property) {
        .utf8 => |value| value.id == .reason_string,
        .utf8_pair => |value| value.id == .user_property,
        else => false,
    };
}

/// Queue state used by blocking correlated-response helpers while they
/// preserve interleaved application packets for the next ordinary read.
const pending_packets_module = @import("runtime/acknowledgement/pending.zig");
pub const PendingPacketState = pending_packets_module.State;

pub const write_property_staging_capacity = 8;
pub const PublishProgress = @import("runtime/acknowledgement/publish_api.zig").Progress;

pub const Connection = @import("runtime/connection.zig").Connection;

pub fn keepAliveTimeout(
    keep_alive_seconds: u16,
) ?std.Io.Clock.Duration {
    if (keep_alive_seconds == 0) return null;
    // Multiplication precedes division so odd values retain the half-second
    // precision required by MQTT instead of being rounded down to seconds.
    const nanoseconds = @divExact(
        @as(i96, keep_alive_seconds) * 3 * std.time.ns_per_s,
        2,
    );
    return .{
        .raw = .fromNanoseconds(nanoseconds),
        .clock = .awake,
    };
}

pub const PublishOptions = struct {
    qos: mqtt.QoS = .at_most_once,
    retain: bool = false,
    dup: bool = false,
    properties: []const mqtt.Property = &.{},
};

pub const SubscribeOptions = struct {
    properties: []const mqtt.Property = &.{},
};

pub const UnsubscribeOptions = struct {
    properties: []const mqtt.Property = &.{},
};

pub const AcknowledgeOptions = struct {
    reason_code: u8 = 0,
    properties: []const mqtt.Property = &.{},
};

pub const OwnedPacket = packet_transport.OwnedPacket;

pub const OwnedConnect = struct {
    packet: OwnedPacket,
    connect: mqtt.Connect,
    /// Optional policy-owned username replacement. The parsed wire fields
    /// continue to borrow packet storage; broker admission may replace the
    /// username with a verified identity that must survive Session handling.
    owned_username: ?[]u8 = null,

    pub fn deinit(self: *OwnedConnect, allocator: std.mem.Allocator) void {
        if (self.owned_username) |username| allocator.free(username);
        self.connect.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }

    pub fn replaceUsername(
        self: *OwnedConnect,
        allocator: std.mem.Allocator,
        username: []const u8,
    ) (mqtt.Error || std.mem.Allocator.Error)!void {
        if (username.len == 0 or username.len > std.math.maxInt(u16)) {
            return error.InvalidUtf8;
        }
        try mqtt.validateUtf8String(username);
        const owned = try allocator.dupe(u8, username);
        if (self.owned_username) |previous| allocator.free(previous);
        self.owned_username = owned;
        self.connect.username = owned;
        self.connect.password = null;
    }
};

pub const OwnedConnAck = struct {
    packet: OwnedPacket,
    connack: mqtt.ConnAck,

    pub fn deinit(self: *OwnedConnAck, allocator: std.mem.Allocator) void {
        self.connack.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedPublish = struct {
    packet: OwnedPacket,
    publish: mqtt.Publish,
    /// Present only when Topic Alias supplied the omitted Topic Name. Normal
    /// names continue borrowing the packet or caller's receive storage.
    owned_topic: ?[]u8 = null,

    pub fn deinit(self: *OwnedPublish, allocator: std.mem.Allocator) void {
        self.publish.deinit(allocator);
        if (self.owned_topic) |topic| allocator.free(topic);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedAck = struct {
    packet: OwnedPacket,
    ack: mqtt.AckPacket,

    pub fn deinit(self: *OwnedAck, allocator: std.mem.Allocator) void {
        self.ack.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedSubscribe = struct {
    packet: OwnedPacket,
    subscribe: mqtt.Subscribe,

    pub fn deinit(self: *OwnedSubscribe, allocator: std.mem.Allocator) void {
        self.subscribe.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedSubAck = struct {
    packet: OwnedPacket,
    suback: mqtt.SubAck,

    pub fn deinit(self: *OwnedSubAck, allocator: std.mem.Allocator) void {
        self.suback.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedUnsubscribe = struct {
    packet: OwnedPacket,
    unsubscribe: mqtt.Unsubscribe,

    pub fn deinit(self: *OwnedUnsubscribe, allocator: std.mem.Allocator) void {
        self.unsubscribe.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedUnsubAck = struct {
    packet: OwnedPacket,
    unsuback: mqtt.UnsubAck,

    pub fn deinit(self: *OwnedUnsubAck, allocator: std.mem.Allocator) void {
        self.unsuback.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedDisconnect = struct {
    packet: OwnedPacket,
    disconnect: mqtt.Disconnect,

    pub fn deinit(self: *OwnedDisconnect, allocator: std.mem.Allocator) void {
        self.disconnect.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedAuth = struct {
    packet: OwnedPacket,
    auth: mqtt.Auth,

    pub fn deinit(self: *OwnedAuth, allocator: std.mem.Allocator) void {
        self.auth.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const BrokerEvent = union(enum) {
    auth: OwnedAuth,
    publish: OwnedPublish,
    subscribe: OwnedSubscribe,
    unsubscribe: OwnedUnsubscribe,
    puback: OwnedAck,
    pubrec: OwnedAck,
    pubrel: OwnedAck,
    pubcomp: OwnedAck,
    pingreq: OwnedPacket,
    disconnect: OwnedDisconnect,

    /// Release all event-owned state. Events returned by an `Into` reader may
    /// borrow that caller's packet buffer; this method leaves it untouched.
    pub fn deinit(
        self: *BrokerEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .auth => |*value| value.deinit(allocator),
            .publish => |*value| value.deinit(allocator),
            .subscribe => |*value| value.deinit(allocator),
            .unsubscribe => |*value| value.deinit(allocator),
            .puback => |*value| value.deinit(allocator),
            .pubrec => |*value| value.deinit(allocator),
            .pubrel => |*value| value.deinit(allocator),
            .pubcomp => |*value| value.deinit(allocator),
            .pingreq => |*value| value.deinit(allocator),
            .disconnect => |*value| value.deinit(allocator),
        }
        self.* = undefined;
    }
};

/// Packets a broker may send after CONNACK. Packet ownership is transferred to
/// the caller, which must call `deinit` after observing the typed value.
pub const ClientPacketEvent = union(enum) {
    auth: OwnedAuth,
    publish: OwnedPublish,
    puback: OwnedAck,
    pubrec: OwnedAck,
    pubrel: OwnedAck,
    pubcomp: OwnedAck,
    pingresp: OwnedPacket,
    disconnect: OwnedDisconnect,

    pub fn deinit(
        self: *ClientPacketEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .auth => |*value| value.deinit(allocator),
            .publish => |*value| value.deinit(allocator),
            .puback => |*value| value.deinit(allocator),
            .pubrec => |*value| value.deinit(allocator),
            .pubrel => |*value| value.deinit(allocator),
            .pubcomp => |*value| value.deinit(allocator),
            .pingresp => |*value| value.deinit(allocator),
            .disconnect => |*value| value.deinit(allocator),
        }
        self.* = undefined;
    }
};

test {
    _ = @import("runtime/tests.zig");
}

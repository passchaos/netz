const std = @import("std");
const connack_preparation = @import("runtime/connack.zig");
const builtin = @import("builtin");
const mqtt = @import("mod.zig");
const redirect = @import("redirect.zig");
const websocket = @import("../websocket/mod.zig");
const websocket_runtime = websocket.runtime;
const http1_runtime = @import("../http1/mod.zig").runtime;
const packet_transport = @import("runtime/packet_transport.zig");
const packet_identifiers = @import("runtime/packet_identifiers.zig");
const stream_io = @import("../internal/stream_io.zig");
const accept_deadline = @import("../internal/accept.zig");
const deadline_policy = @import("../internal/deadline.zig");
const auth_runtime = @import("runtime/auth.zig");
const topic_alias = @import("runtime/topic_alias.zig");
const proxy_protocol = @import("proxy_protocol.zig");
const listener_namespace = @import("listener_namespace.zig");
const tls_stream = @import("../tls/mod.zig").stream;
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
    /// send ordinary traffic at any time, so SUBSCRIBE, UNSUBSCRIBE and PING
    /// preserve those packets for the next typed reader.
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
const ConnectionLimits = struct {
    max_packet_size: usize = 16 * 1024 * 1024,
    max_pending_ping_packets: usize = 256,
    max_pending_packet_bytes: usize = pending_packets_module.default_max_bytes,

    fn from(limits: Limits) ConnectionLimits {
        return .{
            .max_packet_size = limits.max_packet_size,
            .max_pending_ping_packets = limits.max_pending_ping_packets,
            .max_pending_packet_bytes = limits.max_pending_packet_bytes,
        };
    }
};

const ConnectionCapabilities = packed struct(u16) {
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

const PacketTransport = packet_transport.Transport;

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

    fn recordReceived(self: *TrafficCounters, bytes: usize) void {
        _ = self.messages_received.fetchAdd(1, .monotonic);
        _ = self.bytes_received.fetchAdd(@intCast(bytes), .monotonic);
    }

    fn recordSent(self: *TrafficCounters, bytes: usize) void {
        _ = self.messages_sent.fetchAdd(1, .monotonic);
        _ = self.bytes_sent.fetchAdd(@intCast(bytes), .monotonic);
    }

    /// Update one connection-owned receive direction. Connection reads have a
    /// single protocol owner, while snapshots may load these values from
    /// another task; atomic load/store preserves that observation boundary
    /// without paying for a multi-writer read-modify-write operation.
    fn recordReceivedExclusive(self: *TrafficCounters, bytes: usize) void {
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
    fn recordSentExclusive(self: *TrafficCounters, bytes: usize) void {
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

fn applyConnAckNegotiation(
    connection: *Connection,
    connack: mqtt.ConnAck,
    options: ConnectOptions,
) void {
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

fn validateAssignedClientIdentifierForConnect(
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

fn negotiatedOutgoingInflightLimit(local_upper_limit: u16, peer_receive_maximum: u16) u16 {
    // MQTT 5 Receive Maximum is the peer's limit for QoS 1/2 PUBLISH packets
    // that we may have in flight.  Like rumqtt, keep the configured local
    // upper bound as a hard ceiling so a peer cannot enlarge local queue/window
    // state by advertising a larger value in CONNECT/CONNACK.
    return @min(local_upper_limit, peer_receive_maximum);
}

fn earliestClockDeadline(
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

fn appendTopicAliasMaximumSetting(
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

fn problemInformationProperty(property: mqtt.Property) bool {
    return switch (property) {
        .utf8 => |value| value.id == .reason_string,
        .utf8_pair => |value| value.id == .user_property,
        else => false,
    };
}

/// Queue state used by blocking correlated-response helpers while they
/// preserve interleaved application packets for the next ordinary read.
const pending_packets_module = @import("runtime/acknowledgement/pending.zig");
const PendingPacketState = pending_packets_module.State;

pub const write_property_staging_capacity = 8;

pub const Connection = struct {
    const EndpointRole = enum { unestablished, client, server };

    allocator: std.mem.Allocator,
    transport: PacketTransport,
    traffic: TrafficCounters = .{},
    traffic_sink: ?*TrafficCounters = null,
    traffic_sink_deferred: bool = false,
    protocol: mqtt.ProtocolVersion = .v5,
    strict_utf8: bool = false,
    endpoint_role: EndpointRole = .unestablished,
    connect_session_expiry: u32 = 0,
    incoming_connect_level_value: u8 = undefined,
    limits: ConnectionLimits = .{},
    next_packet_id: u16 = 1,
    outgoing_inflight: u16 = 0,
    max_outgoing_inflight: u16 = 16,
    incoming_inflight: u16 = 0,
    max_incoming_inflight: u16 = 16,
    peer_max_packet_size: usize = std.math.maxInt(usize),
    incoming_topic_alias_maximum: u16 = 16,
    peer_topic_alias_maximum: u16 = 0,
    keep_alive_seconds: u16 = 30,
    capabilities: ConnectionCapabilities = .{},
    proxy_v2_require_client_certificate: bool = false,
    packet_identifiers: packet_identifiers.State = .{},
    /// Incoming and outgoing aliases have independent concurrency owners and
    /// are allocated only when their direction first registers a mapping.
    incoming_topic_aliases: ?*topic_alias.Table = null,
    outgoing_topic_aliases: ?*topic_alias.Table = null,
    /// A failed stream write has an unknowable wire prefix: the peer may have
    /// received none, part, or all of the MQTT Control Packet. No later read
    /// or write may reuse connection-scoped state (especially Topic Alias)
    /// after that ambiguity. The owner must close this Network Connection.
    transport_unusable: std.atomic.Value(bool) = .init(false),
    assigned_client_id_ptr: ?[*]u8 = null,
    assigned_client_id_len: u16 = 0,
    authentication: auth_runtime.State = .{},
    /// Shared packet-output storage. MQTT writes are synchronous and a
    /// Connection permits only one writer at a time, so control packets and
    /// PUBLISH can safely reuse one allocation instead of maintaining a
    /// separate growable buffer per operation.
    write_scratch: std.ArrayList(u8) = .empty,
    /// Common synthesized or filtered property sets use caller stack storage.
    /// Larger sets retain this exact-capacity overflow allocation across
    /// writes while the connection's single-writer boundary is held.
    write_property_overflow: ?[]mqtt.Property = null,
    /// Allocated before the first synchronous correlated-response wait.
    /// Ordinary event reads do not allocate this queue state.
    pending_packets: ?*PendingPacketState = null,
    /// Owned metadata from an explicitly trusted PROXY protocol listener.
    /// Keeping it beside rather than inside the transport allows the same
    /// identity model to span raw TCP, TLS, WS, and WSS adapters.
    /// Present only for listeners which explicitly enabled trusted PROXY
    /// protocol parsing. The 296-byte descriptor remains out of line for the
    /// overwhelmingly common direct-connection path.
    proxy_metadata: ?*proxy_protocol.Metadata = null,
    /// Owned broker-listener namespace. The optional pointer carries presence;
    /// MQTT's u16 string bound makes a separate machine-word length needless.
    topic_namespace_ptr: ?[*]u8 = null,
    topic_namespace_len: u16 = 0,

    /// Wrap an already-negotiated WebSocket connection in the shared MQTT
    /// session state. Prefer `mqtt.websocket_runtime.Client`/`Server` unless
    /// the caller owns the WebSocket opening handshake. This consumes `ws`
    /// on both success and allocation failure.
    pub fn initWebSocket(
        allocator: std.mem.Allocator,
        ws: websocket_runtime.Connection,
        protocol: mqtt.ProtocolVersion,
        limits: Limits,
        max_outgoing_inflight: u16,
        topic_alias_maximum: u16,
    ) std.mem.Allocator.Error!Connection {
        return .{
            .allocator = allocator,
            .transport = try .initWebSocket(allocator, ws),
            .protocol = protocol,
            .limits = .from(limits),
            .proxy_v2_require_client_certificate = limits.proxy_v2_require_client_certificate,
            .max_outgoing_inflight = max_outgoing_inflight,
            .incoming_topic_alias_maximum = topic_alias_maximum,
        };
    }

    /// Wrap a TLS client connection in the shared MQTT session state.
    ///
    /// The TLS object owns and closes the underlying TCP stream. As with the
    /// WebSocket adapter, MQTT negotiation and QoS state remain transport
    /// independent after construction.
    pub fn initTls(
        allocator: std.mem.Allocator,
        tls_connection: *http1_runtime.TlsClientConnection,
        options: ConnectOptions,
    ) Connection {
        var connection = initTlsState(allocator, options);
        connection.transport = .initTls(tls_connection);
        return connection;
    }

    fn initTlsState(
        allocator: std.mem.Allocator,
        options: ConnectOptions,
    ) Connection {
        return .{
            .allocator = allocator,
            .transport = undefined,
            .protocol = options.protocol,
            .limits = .from(options.limits),
            .proxy_v2_require_client_certificate = options.limits.proxy_v2_require_client_certificate,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .max_incoming_inflight = options.effectiveReceiveMaximum(),
            .incoming_topic_alias_maximum = options.topic_alias_maximum,
            .capabilities = .{
                .peer_maximum_qos = options.peer_maximum_qos,
                .peer_retain_available = options.peer_retain_available,
            },
        };
    }

    /// Wrap a vail-backed TLS 1.3 client connection. This variant is selected
    /// when the caller configures a client identity because Zig 0.16's standard
    /// TLS client cannot answer CertificateRequest.
    pub fn initVailTls(
        allocator: std.mem.Allocator,
        tls_connection: *tls_stream.ClientConnection,
        options: ConnectOptions,
    ) Connection {
        var connection = initTlsState(allocator, options);
        connection.transport = .initVailTls(tls_connection);
        return connection;
    }

    /// Wrap an established server-side TLS stream in shared MQTT state.
    ///
    /// The TLS connection owns its accepted TCP stream. Broker-side MQTT
    /// negotiation remains centralized in `accept`, exactly as for plain TCP
    /// and WebSocket listeners.
    pub fn initTlsServer(
        allocator: std.mem.Allocator,
        tls_connection: *tls_stream.ServerConnection,
        protocol: mqtt.ProtocolVersion,
        limits: Limits,
        max_outgoing_inflight: u16,
        topic_alias_maximum: u16,
    ) Connection {
        return .{
            .allocator = allocator,
            .transport = .initTlsServer(tls_connection),
            .protocol = protocol,
            .limits = .from(limits),
            .proxy_v2_require_client_certificate = limits.proxy_v2_require_client_certificate,
            .max_outgoing_inflight = max_outgoing_inflight,
            .incoming_topic_alias_maximum = topic_alias_maximum,
        };
    }

    pub fn close(self: *Connection) void {
        self.flushDeferredTrafficCounters();
        self.packet_identifiers.deinit(self.allocator);
        self.clearTopicAliases();
        self.clearAssignedClientId();
        self.authentication.deinit(self.allocator);
        self.write_scratch.deinit(self.allocator);
        self.clearWritePropertyOverflow();
        self.clearPendingPacketState();
        self.clearProxyMetadata();
        self.clearTopicNamespace();
        self.transport.close(self.allocator);
        self.* = undefined;
    }

    /// Prepare connection-exclusive property staging. Common lists use the
    /// caller's stack; larger lists reuse one exact-capacity overflow buffer.
    pub fn writePropertyList(
        self: *Connection,
        stack: *[write_property_staging_capacity]mqtt.Property,
        required: usize,
    ) std.mem.Allocator.Error!std.ArrayList(mqtt.Property) {
        if (required <= stack.len) {
            return .initBuffer(stack[0..required]);
        }
        if (self.write_property_overflow) |storage| {
            if (required <= storage.len) {
                return .initBuffer(storage[0..required]);
            }
            const grown = try self.allocator.realloc(storage, required);
            self.write_property_overflow = grown;
            return .initBuffer(grown);
        }
        const storage = try self.allocator.alloc(mqtt.Property, required);
        self.write_property_overflow = storage;
        return .initBuffer(storage);
    }

    fn clearWritePropertyOverflow(self: *Connection) void {
        if (self.write_property_overflow) |storage| {
            self.allocator.free(storage);
            self.write_property_overflow = null;
        }
    }

    /// Attach aggregate counters before the connection is driven concurrently.
    /// Existing private traffic is copied into a newly attached sink, which
    /// preserves an already parsed CONNECT during broker handoff.
    pub fn attachTrafficCounters(
        self: *Connection,
        counters: *TrafficCounters,
    ) void {
        if (self.traffic_sink == counters and !self.traffic_sink_deferred) {
            return;
        }
        std.debug.assert(self.traffic_sink == null);
        counters.add(self.traffic.stats());
        // Traffic observed before attachment is now represented by the
        // aggregate sink. Reset the private delta so a later Connection move
        // or defensive reattachment cannot charge those packets twice.
        self.traffic = .{};
        self.traffic_sink = counters;
    }

    /// Attach a sink whose live delta remains connection-owned until an
    /// explicit flush or close. Owners that can include active connection
    /// snapshots in their aggregate view avoid two shared atomic RMWs per
    /// packet while retaining exact lifetime totals.
    pub fn attachDeferredTrafficCounters(
        self: *Connection,
        counters: *TrafficCounters,
    ) void {
        if (self.traffic_sink == counters and self.traffic_sink_deferred) {
            return;
        }
        std.debug.assert(self.traffic_sink == null);
        self.traffic_sink = counters;
        self.traffic_sink_deferred = true;
    }

    /// Move a deferred connection delta into its shared lifetime sink once.
    /// Callers must first stop both direction owners or otherwise serialize
    /// this boundary with them.
    pub fn flushDeferredTrafficCounters(self: *Connection) void {
        if (!self.traffic_sink_deferred) return;
        const counters = self.traffic_sink orelse unreachable;
        counters.add(self.traffic.stats());
        self.traffic = .{};
        self.traffic_sink = null;
        self.traffic_sink_deferred = false;
    }

    pub fn trafficStats(self: *const Connection) TrafficStats {
        return self.traffic.stats();
    }

    /// Whether this Network Connection can still carry MQTT packets. A write
    /// error or explicit shutdown retires it permanently.
    pub fn isUsable(self: *const Connection) bool {
        return !self.transport_unusable.load(.acquire);
    }

    /// Wake a concurrent TCP reader while retaining connection ownership.
    pub fn shutdown(self: *Connection) Error!void {
        self.transport_unusable.store(true, .release);
        try self.transport.shutdown();
    }

    /// Retire the connection and interrupt a blocking reader or writer on any
    /// transport, including MQTT-over-WebSocket. Ownership remains with this
    /// connection until `close`.
    pub fn interrupt(self: *Connection) Error!void {
        self.transport_unusable.store(true, .release);
        try self.transport.interrupt();
    }

    /// Return the verified client certificate chain for an mTLS server
    /// connection. The DER slices are owned by the transport and remain valid
    /// until `close`; anonymous or non-mTLS transports return null.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        return self.transport.peerCertificates();
    }

    /// Return the negotiated TLS ALPN protocol for native MQTT-over-TLS or
    /// vail-backed WSS. Cleartext and standard-library TLS without ALPN return
    /// null. The borrowed value remains valid until `close`.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return self.transport.negotiatedAlpn();
    }

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        return self.transport.negotiatedTlsProtocol();
    }

    pub fn wasTlsSessionResumed(self: *const Connection) ?bool {
        return self.transport.wasTlsSessionResumed();
    }

    pub fn takeTls12SessionTicket(
        self: *Connection,
    ) ?tls_stream.Tls12SessionTicket {
        return self.transport.takeTls12SessionTicket();
    }

    pub fn takeTls13SessionTicket(
        self: *Connection,
    ) Error!?tls_stream.Tls13SessionTicket {
        return self.transport.takeTls13SessionTicket();
    }

    /// Return authenticated TLS cipher-suite metadata for native TLS or
    /// vail-backed WSS. Other transports return null.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.transport.negotiatedCipherSuite();
    }

    /// Return the transcript/HKDF hash implied by the negotiated TLS suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        return self.transport.negotiatedTranscriptHash();
    }

    /// Start a TLS 1.3 application traffic-key update for native TLS or WSS.
    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        return self.transport.updateTrafficKeys(request_peer_update);
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        return self.transport.keyUpdateCounts();
    }

    /// Export RFC 8446 channel-bound keying material from vail-backed native
    /// TLS or WSS. Cleartext and standard-library TLS return
    /// `ExporterUnavailable` rather than silently producing unbound bytes.
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        return self.transport.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    /// Return trusted PROXY protocol metadata, if this listener required it.
    /// The borrowed value remains valid until `close`.
    pub fn proxyMetadata(
        self: *const Connection,
    ) ?*const proxy_protocol.Metadata {
        return self.proxy_metadata;
    }

    /// Return a PROXY v2 SSL commonName only when this connection's listener
    /// explicitly required a verified client certificate assertion. This
    /// prevents callers from accidentally promoting an optional TLV string to
    /// authenticated identity.
    pub fn authenticatedProxyCommonName(
        self: *const Connection,
    ) ?[]const u8 {
        if (!self.proxy_v2_require_client_certificate) return null;
        const metadata = self.proxyMetadata() orelse return null;
        if (metadata.version != .v2 or metadata.command != .proxy) return null;
        const tls = metadata.tls orelse return null;
        if (!tls.client_ssl or !tls.verified or
            (!tls.client_certificate_connection and
                !tls.client_certificate_session))
        {
            return null;
        }
        return tls.common_name;
    }

    /// Transfer owned trusted-proxy metadata into this connection. This may be
    /// called at most once, after the preface is consumed and before the
    /// connection escapes its transport adapter. Allocation failure leaves the
    /// caller-owned value unchanged; success transfers its nested allocations.
    pub fn attachProxyMetadata(
        self: *Connection,
        metadata: proxy_protocol.Metadata,
    ) std.mem.Allocator.Error!void {
        std.debug.assert(self.proxy_metadata == null);
        const owned = try self.allocator.create(proxy_protocol.Metadata);
        owned.* = metadata;
        self.proxy_metadata = owned;
    }

    fn clearProxyMetadata(self: *Connection) void {
        const metadata = self.proxy_metadata orelse return;
        metadata.deinit();
        self.allocator.destroy(metadata);
        self.proxy_metadata = null;
    }

    fn ensureIncomingTopicAliases(
        self: *Connection,
    ) std.mem.Allocator.Error!*topic_alias.Table {
        if (self.incoming_topic_aliases) |aliases| return aliases;
        const aliases = try self.allocator.create(topic_alias.Table);
        aliases.* = .{};
        self.incoming_topic_aliases = aliases;
        return aliases;
    }

    fn ensureOutgoingTopicAliases(
        self: *Connection,
    ) std.mem.Allocator.Error!*topic_alias.Table {
        if (self.outgoing_topic_aliases) |aliases| return aliases;
        const aliases = try self.allocator.create(topic_alias.Table);
        aliases.* = .{};
        self.outgoing_topic_aliases = aliases;
        return aliases;
    }

    fn clearTopicAliases(self: *Connection) void {
        self.clearIncomingTopicAliases();
        self.clearOutgoingTopicAliases();
    }

    fn clearIncomingTopicAliases(self: *Connection) void {
        if (self.incoming_topic_aliases) |aliases| {
            aliases.deinit(self.allocator);
            self.allocator.destroy(aliases);
            self.incoming_topic_aliases = null;
        }
    }

    fn clearOutgoingTopicAliases(self: *Connection) void {
        if (self.outgoing_topic_aliases) |aliases| {
            aliases.deinit(self.allocator);
            self.allocator.destroy(aliases);
            self.outgoing_topic_aliases = null;
        }
    }

    fn incomingTopicAlias(
        self: *const Connection,
        alias: u16,
    ) ?[]const u8 {
        const aliases = self.incoming_topic_aliases orelse return null;
        return aliases.get(alias);
    }

    fn outgoingTopicAlias(
        self: *const Connection,
        alias: u16,
    ) ?[]const u8 {
        const aliases = self.outgoing_topic_aliases orelse return null;
        return aliases.get(alias);
    }

    pub fn setTopicNamespace(
        self: *Connection,
        prefix: []const u8,
    ) Error!void {
        const validated = try listener_namespace.Namespace.init(prefix);
        const replacement = if (validated.prefix.len == 0)
            null
        else
            try self.allocator.dupe(u8, validated.prefix);
        self.clearTopicNamespace();
        if (replacement) |owned| {
            self.topic_namespace_ptr = owned.ptr;
            self.topic_namespace_len = @intCast(owned.len);
        }
    }

    pub fn topicNamespace(
        self: *const Connection,
    ) []const u8 {
        const ptr = self.topic_namespace_ptr orelse return &.{};
        return ptr[0..self.topic_namespace_len];
    }

    fn clearTopicNamespace(self: *Connection) void {
        const ptr = self.topic_namespace_ptr orelse return;
        self.allocator.free(ptr[0..self.topic_namespace_len]);
        self.topic_namespace_ptr = null;
        self.topic_namespace_len = 0;
    }

    fn incomingConnectLevel(self: *const Connection) ?u8 {
        return if (self.capabilities.has_incoming_connect_level)
            self.incoming_connect_level_value
        else
            null;
    }

    fn setIncomingConnectLevel(
        self: *Connection,
        maybe_level: ?u8,
    ) void {
        const level = maybe_level orelse {
            self.capabilities.has_incoming_connect_level = false;
            return;
        };
        self.incoming_connect_level_value = level;
        self.capabilities.has_incoming_connect_level = true;
    }

    pub fn visibleTopic(
        self: *const Connection,
        canonical_topic: []const u8,
    ) listener_namespace.Error![]const u8 {
        return (listener_namespace.Namespace{
            .prefix = self.topicNamespace(),
        }).visibleTopic(canonical_topic);
    }

    /// Server-side Maximum QoS negotiated for this Network Connection.
    /// Listener-aware brokers use it for subscription grants and delivery.
    pub fn localMaximumQoS(self: *const Connection) mqtt.QoS {
        return self.capabilities.local_maximum_qos;
    }

    /// Client-side Maximum QoS advertised by the connected broker.
    pub fn peerMaximumQoS(self: *const Connection) mqtt.QoS {
        return self.capabilities.peer_maximum_qos;
    }

    pub fn peerRetainAvailable(self: *const Connection) bool {
        return self.capabilities.peer_retain_available and
            self.capabilities.outgoing_retain_enabled;
    }

    pub fn setPeerPublishCapabilities(
        self: *Connection,
        maximum_qos: mqtt.QoS,
        retain_available: bool,
    ) void {
        self.capabilities.peer_maximum_qos = maximum_qos;
        self.capabilities.peer_retain_available = retain_available;
    }

    pub fn peerRequestedProblemInformation(self: *const Connection) bool {
        return self.capabilities.peer_requested_problem_information;
    }

    /// Maximum complete MQTT Control Packet the peer advertised it can
    /// receive. Reconnect preflights deferred acknowledgements against this
    /// value before committing durable transaction state.
    pub fn peerMaximumPacketSize(self: *const Connection) usize {
        return self.peer_max_packet_size;
    }

    /// Number of aliases registered for server-bound PUBLISH packets in this
    /// Network Connection. Reconnect clients use this to verify fresh state.
    pub fn outgoingTopicAliasCount(self: *const Connection) usize {
        const aliases = self.outgoing_topic_aliases orelse return 0;
        return aliases.count();
    }

    pub fn incomingTopicAliasCount(self: *const Connection) usize {
        const aliases = self.incoming_topic_aliases orelse return 0;
        return aliases.count();
    }

    /// Return the proxied source IP when available, otherwise the connected
    /// transport peer. PROXY UNKNOWN/LOCAL deliberately use the latter.
    pub fn remoteAddress(self: *const Connection) net.IpAddress {
        if (self.proxy_metadata) |metadata| {
            if (metadata.sourceAddress()) |address| return address;
        }
        return self.transport.remoteAddress();
    }

    /// Return the MQTT 5 Client Identifier assigned for an empty CONNECT ID.
    ///
    /// The value is deep-owned by this Connection, so it remains available
    /// when `Client.connect` discards the transient CONNACK object.
    pub fn assignedClientId(
        self: *const Connection,
    ) ?[]const u8 {
        const ptr = self.assigned_client_id_ptr orelse return null;
        return ptr[0..self.assigned_client_id_len];
    }

    fn setAssignedClientId(
        self: *Connection,
        client_id: []const u8,
    ) Error!void {
        std.debug.assert(self.assigned_client_id_ptr == null);
        const len = std.math.cast(u16, client_id.len) orelse
            return error.InvalidClientId;
        const owned = try self.allocator.dupe(u8, client_id);
        self.assigned_client_id_ptr = owned.ptr;
        self.assigned_client_id_len = len;
    }

    fn clearAssignedClientId(self: *Connection) void {
        const ptr = self.assigned_client_id_ptr orelse return;
        self.allocator.free(ptr[0..self.assigned_client_id_len]);
        self.assigned_client_id_ptr = null;
        self.assigned_client_id_len = 0;
    }

    /// Complete the broker side of MQTT CONNECT on an already-open transport.
    ///
    /// Transport adapters call this after their own opening handshake, which
    /// keeps all MQTT capability and inflight negotiation in one state machine.
    pub fn accept(
        self: *Connection,
        options: AcceptOptions,
    ) Error!AcceptedClient {
        const allocator = self.allocator;
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(allocator);
        return pending.finish(options);
    }

    /// Parse CONNECT and apply peer capability limits without sending CONNACK.
    pub fn acceptPending(
        self: *Connection,
        options: AcceptOptions,
    ) Error!PendingAcceptedClient {
        const deadline = if (options.connect_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            break :blk self.transport.deadlineFromNow(timeout);
        } else null;
        return self.acceptPendingBefore(options, deadline);
    }

    /// Parse CONNECT under the earlier of a caller-owned absolute deadline and
    /// `options.connect_timeout`. Transport adapters use this to preserve one
    /// budget across an outer TLS or WebSocket handshake and MQTT admission.
    pub fn acceptPendingWithDeadline(
        self: *Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        const io = self.transport.ioHandle();
        _ = try deadline_policy.usableAwake(io, deadline);
        const phase_deadline = if (options.connect_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            break :blk self.transport.deadlineFromNow(timeout);
        } else null;
        return self.acceptPendingBefore(
            options,
            earliestClockDeadline(deadline, phase_deadline),
        );
    }

    fn acceptPendingBefore(
        self: *Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingAcceptedClient {
        if (!options.accepted_protocol_versions.any()) {
            return error.InvalidProperty;
        }
        self.strict_utf8 = options.strict_utf8;
        if (options.traffic_counters) |counters| {
            if (options.traffic_counters_deferred) {
                self.attachDeferredTrafficCounters(counters);
            } else {
                self.attachTrafficCounters(counters);
            }
        }
        var connect = (if (deadline) |absolute|
            self.readConnectPacketWithDeadline(absolute)
        else
            self.readConnectPacket()) catch |err| {
            self.writeConnectErrorConnAckMaybeBefore(err, deadline) catch {};
            return err;
        };
        errdefer connect.deinit(self.allocator);
        const client_id_was_empty = connect.connect.client_id.len == 0;
        if (!options.accepted_protocol_versions.allows(
            connect.connect.protocol,
        )) {
            // Preserve the parsed CONNECT solely long enough for `finish` to
            // emit the version-specific refusal. No capability, Will, or
            // authentication state is applied for a disabled version.
            const owned_connection = self.*;
            self.* = undefined;
            return .{
                .connection = owned_connection,
                .connect = connect,
                .admission_deadline = deadline,
                .protocol_allowed = false,
                .client_id_was_empty = client_id_was_empty,
            };
        }
        const maximum_qos = options.maximum_qos orelse
            mqtt.QoS.exactly_once;
        if (connect.connect.will) |will| {
            if (@intFromEnum(will.qos) > @intFromEnum(maximum_qos)) {
                if (connect.connect.protocol == .v5) {
                    try self.writeConnAckMaybeBefore(
                        .{ .reason_code = 0x9b },
                        deadline,
                    );
                }
                return error.InvalidQoS;
            }
            if (will.retain and !options.retain_available) {
                if (connect.connect.protocol == .v5) {
                    try self.writeConnAckMaybeBefore(
                        .{ .reason_code = 0x9a },
                        deadline,
                    );
                }
                return error.InvalidProperty;
            }
        }
        if (mqtt.receiveMaximum(connect.connect.properties)) |receive_maximum| {
            self.max_outgoing_inflight = negotiatedOutgoingInflightLimit(
                self.max_outgoing_inflight,
                receive_maximum,
            );
        }
        if (mqtt.maximumPacketSize(connect.connect.properties)) |maximum_packet_size| {
            self.peer_max_packet_size = maximum_packet_size;
        }
        if (mqtt.topicAliasMaximum(connect.connect.properties)) |topic_alias_maximum| {
            self.peer_topic_alias_maximum = topic_alias_maximum;
        }
        try self.authentication.beginConnect(
            self.allocator,
            connect.connect.properties,
        );
        self.capabilities.peer_requested_problem_information =
            mqtt.requestProblemInformation(
                connect.connect.properties,
            ) orelse true;
        const owned_connection = self.*;
        self.* = undefined;
        return .{
            .connection = owned_connection,
            .connect = connect,
            .admission_deadline = deadline,
            .client_id_was_empty = client_id_was_empty,
        };
    }

    /// Send CONNECT and process CONNACK on an already-open transport.
    pub fn establishClient(
        self: *Connection,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        const deadline = if (options.connect_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            break :blk self.transport.deadlineFromNow(timeout);
        } else null;
        return self.establishClientBefore(options, deadline);
    }

    pub fn establishClientWithDeadline(
        self: *Connection,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        const phase_deadline = if (options.connect_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            break :blk self.transport.deadlineFromNow(timeout);
        } else null;
        // Reuse the caller's original timestamp rather than converting its
        // remaining duration back into a fresh timeout. That keeps time spent
        // in DNS/TCP setup charged to the same end-to-end budget.
        return self.establishClientBefore(
            options,
            earliestClockDeadline(deadline, phase_deadline),
        );
    }

    pub fn establishClientWithTimeout(
        self: *Connection,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.establishClientWithDeadline(
            options,
            .fromNow(
                self.transport.ioHandle(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn establishClientBefore(
        self: *Connection,
        options: ConnectOptions,
        connect_deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.max_outgoing_packet_size == 0 or
            options.max_outgoing_inflight == 0 or
            options.receive_maximum == 0)
        {
            return error.InvalidProperty;
        }
        try self.validateOutgoingPacketType(.connect);
        // This method transfers `self` into the returned attempt. Capture the
        // allocator before that move so deferred temporary cleanup never reads
        // the deliberately undefined moved-from connection.
        const allocator = self.allocator;
        // The CONNECT value is also the client's local keep-alive schedule.
        // A successful MQTT 5 CONNACK may replace it below with Server Keep
        // Alive, but an omitted property must retain the requested interval.
        self.keep_alive_seconds = options.keep_alive_seconds;
        self.endpoint_role = .client;
        self.strict_utf8 = options.strict_utf8;
        self.connect_session_expiry = mqtt.sessionExpiryInterval(
            options.properties,
        ) orelse 0;
        self.write_scratch.clearRetainingCapacity();
        const receive_maximum = options.effectiveReceiveMaximum();
        const add_receive_maximum = options.protocol == .v5 and
            mqtt.receiveMaximum(options.properties) == null;
        const add_maximum_packet_size = options.protocol == .v5 and
            mqtt.maximumPacketSize(options.properties) == null and
            options.limits.max_packet_size <= std.math.maxInt(u32);
        const add_topic_alias_maximum = options.protocol == .v5 and
            options.topic_alias_maximum != 0 and
            mqtt.topicAliasMaximum(options.properties) == null;
        const generated_property_count =
            @as(usize, @intFromBool(add_receive_maximum)) +
            @intFromBool(add_maximum_packet_size) +
            @intFromBool(add_topic_alias_maximum);
        var property_stack: [write_property_staging_capacity]mqtt.Property =
            undefined;
        var properties = try self.writePropertyList(
            &property_stack,
            std.math.add(
                usize,
                options.properties.len,
                generated_property_count,
            ) catch
                return error.OutOfMemory,
        );
        properties.appendSliceAssumeCapacity(options.properties);
        if (add_receive_maximum) {
            properties.appendAssumeCapacity(.{ .two_byte = .{
                .id = .receive_maximum,
                .value = receive_maximum,
            } });
        }
        if (add_maximum_packet_size) {
            properties.appendAssumeCapacity(.{ .four_byte = .{
                .id = .maximum_packet_size,
                .value = @intCast(options.limits.max_packet_size),
            } });
        }
        if (add_topic_alias_maximum) {
            properties.appendAssumeCapacity(.{ .two_byte = .{
                .id = .topic_alias_maximum,
                .value = options.topic_alias_maximum,
            } });
        }
        if (options.protocol == .v5) {
            self.max_incoming_inflight =
                mqtt.receiveMaximum(properties.items) orelse
                receive_maximum;
            self.incoming_topic_alias_maximum =
                mqtt.topicAliasMaximum(properties.items) orelse
                self.incoming_topic_alias_maximum;
        }
        try mqtt.writeConnectPacket(
            &self.write_scratch,
            allocator,
            options.protocol,
            .{
                .client_id = options.client_id,
                .bridge_mode = options.bridge_mode,
                .clean_start = options.clean_start,
                .keep_alive_seconds = options.keep_alive_seconds,
                .properties = properties.items,
                .will = options.will,
                .username = options.username,
                .password = options.password,
            },
        );
        try self.authentication.beginConnect(
            allocator,
            properties.items,
        );
        if (connect_deadline) |deadline|
            try self.writeGeneratedPacketWithDeadline(
                self.write_scratch.items,
                .connect,
                deadline,
            )
        else
            try self.writeGeneratedPacket(self.write_scratch.items, .connect);
        const auth_handler = options.authentication;
        var auth_rounds: usize = 0;
        var connack: OwnedConnAck = while (true) {
            var packet = if (connect_deadline) |deadline|
                try self.readPacketWithDeadline(deadline)
            else
                try self.readPacket();
            errdefer packet.deinit(allocator);
            switch (packet.fixed.packet_type) {
                .auth => {
                    if (auth_handler == null) {
                        return error.AuthenticationNotConfigured;
                    }
                    auth_rounds += 1;
                    if (auth_rounds > 64) {
                        return error.AuthenticationInProgress;
                    }
                    var auth = try self.parseIncomingAuth(
                        packet.bytes,
                    );
                    defer auth.deinit(allocator);
                    self.authentication.receiveInitialAuth(auth) catch |err| {
                        if (err == error.AuthenticationMethodMismatch or
                            err == error.InvalidAuthenticationState)
                        {
                            self.sendAuthenticationProtocolError();
                        }
                        return err;
                    };
                    const response = try auth_handler.?.respond(
                        auth_handler.?.context,
                        auth,
                    );
                    self.authentication.validatePeerProperties(
                        response,
                    ) catch |err| {
                        if (err == error.AuthenticationMethodMismatch) {
                            self.sendAuthenticationProtocolError();
                        }
                        return err;
                    };
                    if (connect_deadline) |deadline|
                        try self.writeAuthWithDeadline(
                            0x18,
                            response,
                            deadline,
                        )
                    else
                        try self.writeAuth(0x18, response);
                    packet.deinit(allocator);
                },
                .connack => {
                    var value = try mqtt.ConnAck.parse(
                        allocator,
                        self.protocol,
                        packet.bytes,
                    );
                    errdefer value.deinit(allocator);
                    if (self.protocol == .v3_1 and
                        options.v3_1_connack_mode == .mosquitto)
                    {
                        value.session_present =
                            value.mosquittoV31SessionPresent();
                        if (value.session_present and value.reason_code != 0) {
                            return error.InvalidFlags;
                        }
                    }
                    try self.validateIncomingProperties(value.properties);
                    if (options.clean_start and value.session_present) {
                        return error.InvalidFlags;
                    }
                    try validateAssignedClientIdentifierForConnect(
                        self.protocol,
                        options.client_id.len == 0,
                        value.reason_code == 0,
                        mqtt.assignedClientIdentifier(value.properties),
                    );
                    if (mqtt.responseInformation(value.properties) != null and
                        mqtt.requestResponseInformation(options.properties) !=
                            true)
                    {
                        return error.InvalidProperty;
                    }
                    self.authentication
                        .receiveInitialConnAck(value) catch |err| {
                        if (err == error.AuthenticationMethodMismatch) {
                            self.sendAuthenticationProtocolError();
                        }
                        return err;
                    };
                    break OwnedConnAck{
                        .packet = packet,
                        .connack = value,
                    };
                },
                else => return error.UnexpectedPacket,
            }
        };
        errdefer connack.deinit(allocator);
        if (connack.connack.reason_code != 0) {
            self.close();
            return .{ .connection = null, .connack = connack };
        }
        applyConnAckNegotiation(self, connack.connack, options);
        if (mqtt.assignedClientIdentifier(
            connack.connack.properties,
        )) |client_id| {
            try self.setAssignedClientId(client_id);
        }

        const owned_connection = self.*;
        self.* = undefined;
        return .{ .connection = owned_connection, .connack = connack };
    }

    pub fn readConnect(self: *Connection) Error!OwnedConnect {
        const packet = try self.readPacket();
        return self.finishReadConnect(packet);
    }

    fn readConnectPacket(self: *Connection) Error!OwnedConnect {
        const packet = try self.readUnvalidatedTransportPacket();
        return self.finishReadConnect(.{
            .bytes = packet.bytes,
            .fixed = packet.fixed,
            .owns_bytes = packet.owns_bytes,
            .prefix_len = packet.prefix_len,
        });
    }

    pub fn readConnectWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedConnect {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = self.transport.deadlineFromNow(timeout);
        return self.readConnectWithDeadline(deadline);
    }

    /// Read CONNECT under a caller-owned absolute deadline. Partial fixed
    /// headers, Remaining Length, and payload bytes remain transport-buffered
    /// and can be resumed by a later receive attempt.
    pub fn readConnectWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedConnect {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        const packet = try self.readPacketWithDeadline(deadline);
        return self.finishReadConnect(packet);
    }

    fn readConnectPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedConnect {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        const packet = try self.readUnvalidatedTransportPacketWithDeadline(
            deadline,
        );
        return self.finishReadConnect(.{
            .bytes = packet.bytes,
            .fixed = packet.fixed,
            .owns_bytes = packet.owns_bytes,
            .prefix_len = packet.prefix_len,
        });
    }

    fn finishReadConnect(
        self: *Connection,
        packet_value: OwnedPacket,
    ) Error!OwnedConnect {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        self.setIncomingConnectLevel(null);
        if (packet.fixed.packet_type != .connect) return error.UnexpectedPacket;
        self.setIncomingConnectLevel(
            mqtt.connectProtocolLevel(packet.bytes) catch null,
        );
        var connect = mqtt.Connect.parse(
            self.allocator,
            packet.bytes,
        ) catch |err| return err;
        errdefer connect.deinit(self.allocator);
        try self.validateIncomingConnectUtf8(connect);
        self.protocol = connect.protocol;
        self.endpoint_role = .server;
        self.connect_session_expiry = mqtt.sessionExpiryInterval(
            connect.properties,
        ) orelse 0;
        self.keep_alive_seconds = connect.keep_alive_seconds;
        return .{ .packet = packet, .connect = connect };
    }

    fn writeConnectErrorConnAckMaybeBefore(
        self: *Connection,
        err: anyerror,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        const raw_level = self.incomingConnectLevel() orelse return;
        const level = raw_level & 0x7f;
        const response_protocol: mqtt.ProtocolVersion = switch (level) {
            3 => .v3_1,
            4 => .v3_1_1,
            else => .v5,
        };
        const reason_code: u8 = switch (response_protocol) {
            .v3_1, .v3_1_1 => switch (err) {
                error.InvalidProtocolLevel => 0x01,
                error.InvalidClientId => 0x02,
                else => return,
            },
            .v5 => switch (err) {
                error.InvalidProtocolLevel => 0x84,
                error.InvalidClientId => 0x85,
                error.InvalidProperty => 0x82,
                error.InvalidTopic => 0x90,
                error.InvalidPacketType,
                error.InvalidFlags,
                error.InvalidQoS,
                error.InvalidPropertyIdentifier,
                error.MalformedPropertyContext,
                error.MalformedSubscriptionOptions,
                error.BufferTooShort,
                error.MalformedRemainingLength,
                error.RemainingLengthTooLarge,
                error.InvalidUtf8,
                => 0x81,
                else => return,
            },
        };
        self.protocol = response_protocol;
        var encoded: [mqtt.ConnAck.no_properties_max_len]u8 = undefined;
        const bytes = try mqtt.ConnAck.writeNoPropertiesInto(
            &encoded,
            response_protocol,
            false,
            reason_code,
        );
        if (deadline) |absolute|
            try self.writeGeneratedPacketWithDeadline(
                bytes,
                .connack,
                absolute,
            )
        else
            try self.writeGeneratedPacket(bytes, .connack);
    }

    pub fn writeConnAck(self: *Connection, options: ConnAckOptions) Error!void {
        return self.writeConnAckMaybeBefore(options, null);
    }

    pub fn writeConnAckWithDeadline(
        self: *Connection,
        options: ConnAckOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        return self.writeConnAckMaybeBefore(options, deadline);
    }

    fn prepareConnAck(self: *Connection, options: ConnAckOptions) Error!connack_preparation.Prepared {
        return self.prepareConnAckMode(options, false);
    }

    fn prepareConnAckMode(self: *Connection, options: ConnAckOptions, reuse_scratch: bool) Error!connack_preparation.Prepared {
        if (!self.isUsable()) return error.ConnectionClosed;
        try self.validateOutgoingPacketType(.connack);
        try self.authentication.ensurePacketAllowed(.connack);
        return if (reuse_scratch) connack_preparation.prepareReusingScratch(self, options) else connack_preparation.prepare(self, options);
    }

    fn writePreparedConnAckMaybeBefore(
        self: *Connection,
        prepared: *connack_preparation.Prepared,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        std.debug.assert(prepared.owner == self and !prepared.written);
        if (deadline) |absolute|
            try self.writeGeneratedPacketWithDeadline(prepared.bytes(), .connack, absolute)
        else
            try self.writeGeneratedPacket(prepared.bytes(), .connack);
        prepared.apply(self);
        prepared.written = true;
    }

    fn writeConnAckMaybeBefore(
        self: *Connection,
        options: ConnAckOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        var prepared = try self.prepareConnAckMode(options, true);
        defer prepared.deinit();
        defer prepared.returnScratch(self);
        try self.writePreparedConnAckMaybeBefore(&prepared, deadline);
    }

    pub fn readConnAck(self: *Connection) Error!OwnedConnAck {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .connack) return error.UnexpectedPacket;
        var connack = try mqtt.ConnAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer connack.deinit(self.allocator);
        try self.validateIncomingProperties(connack.properties);
        return .{ .packet = packet, .connack = connack };
    }

    pub fn publish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!void {
        const packet_id = try self.writePublish(topic, payload, options);
        if (packet_id) |id| try self.completePublish(id, options.qos);
    }

    pub fn writePublish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!?u16 {
        try self.validateOutgoingPublish(
            topic,
            options.qos,
            options.retain,
            options.properties,
        );

        const packet_id = if (options.qos == .at_most_once) null else try self.reserveOutgoingPublish(options.qos);
        errdefer if (packet_id) |id| self.releaseOutgoingPublish(id, options.qos);

        try self.writeValidatedPublish(topic, payload, .{
            .qos = options.qos,
            .retain = options.retain,
            .dup = options.dup,
            .packet_id = packet_id,
            .properties = options.properties,
        });
        return packet_id;
    }

    /// Add or reuse a negotiated Topic Alias for a connection-local PUBLISH.
    ///
    /// The caller retains property-list ownership and must pass the returned
    /// Topic Name plus the same list to the outgoing PUBLISH writer. Alias
    /// state is committed there after local preflight checks and before
    /// transport bytes are sent.
    /// Existing explicit aliases are left untouched, and a full alias table
    /// falls back to the full topic.
    pub fn prepareAutomaticTopicAlias(
        self: *Connection,
        topic: []const u8,
        properties: *std.ArrayList(mqtt.Property),
    ) Error![]const u8 {
        return self.prepareAutomaticTopicAliasInternal(
            topic,
            properties,
            false,
        );
    }

    /// Variant for internal writers that reserved one additional property slot
    /// in stack-first or retained overflow storage.
    pub fn prepareAutomaticTopicAliasAssumeCapacity(
        self: *Connection,
        topic: []const u8,
        properties: *std.ArrayList(mqtt.Property),
    ) Error![]const u8 {
        return self.prepareAutomaticTopicAliasInternal(
            topic,
            properties,
            true,
        );
    }

    fn prepareAutomaticTopicAliasInternal(
        self: *Connection,
        topic: []const u8,
        properties: *std.ArrayList(mqtt.Property),
        comptime assume_capacity: bool,
    ) Error![]const u8 {
        if (self.protocol != .v5 or topic.len == 0 or
            self.peer_topic_alias_maximum == 0 or
            mqtt.topicAlias(properties.items) != null)
        {
            return topic;
        }
        if (self.outgoing_topic_aliases) |aliases| {
            if (aliases.findTopic(
                topic,
                self.peer_topic_alias_maximum,
            )) |alias| {
                const property: mqtt.Property = .{ .two_byte = .{
                    .id = .topic_alias,
                    .value = alias,
                } };
                if (assume_capacity) {
                    properties.appendAssumeCapacity(property);
                } else {
                    try properties.append(self.allocator, property);
                }
                return "";
            }
        }
        const alias = if (self.outgoing_topic_aliases) |aliases|
            aliases.firstUnused(self.peer_topic_alias_maximum) orelse
                return topic
        else
            @as(u16, 1);
        const property: mqtt.Property = .{ .two_byte = .{
            .id = .topic_alias,
            .value = alias,
        } };
        if (assume_capacity) {
            properties.appendAssumeCapacity(property);
        } else {
            try properties.append(self.allocator, property);
        }
        return topic;
    }

    /// Write one Session packet encoded under the broker state lock.
    ///
    /// The byte slice is detached from Session Store ownership, allowing the
    /// broker to release its global lock before transport I/O.
    pub fn writeEncodedSessionPacket(
        self: *Connection,
        bytes: []u8,
    ) Error!void {
        try self.writePacket(bytes);
    }

    /// Send one detached Session packet while applying only this Network
    /// Connection's Topic Alias state. PUBLISH payload and property values
    /// remain borrowed from `bytes`; PUBREL is already in its final wire form.
    pub fn writeEncodedSessionTransmission(
        self: *Connection,
        bytes: []u8,
    ) Error!void {
        const fixed = try mqtt.FixedHeader.parse(bytes);
        if (fixed.packet_type == .pubrel) return self.writePacket(bytes);
        if (fixed.packet_type != .publish) return error.InvalidPacketType;
        var publish_packet = try mqtt.Publish.parse(
            self.allocator,
            self.protocol,
            bytes,
        );
        defer publish_packet.deinit(self.allocator);
        return self.writeSessionPublish(.{
            .topic = publish_packet.topic,
            .payload = publish_packet.payload,
            .qos = publish_packet.qos,
            .retain = publish_packet.retain,
            .dup = publish_packet.dup,
            .packet_id = publish_packet.packet_id orelse 0,
            .properties = publish_packet.properties,
            .message_expiry_interval = mqtt.messageExpiryInterval(
                publish_packet.properties,
            ),
        });
    }

    /// Write a detached broker Session transmission whose Topic Name is
    /// already projected through the destination listener namespace and whose
    /// QoS is already capped to that listener's Maximum QoS. All borrowed
    /// slices must remain valid through this synchronous call.
    pub fn writePreparedSessionTransmission(
        self: *Connection,
        transmission: @import("session/mod.zig").Transmission,
    ) Error!void {
        return switch (transmission) {
            .publish => |publish_value| self.writeSessionPublish(
                publish_value,
            ),
            .pubrel => |pubrel| self.writeSessionPubRel(pubrel),
        };
    }

    /// Write an already-selected durable Session transmission while projecting
    /// its canonical topic through this connection's listener namespace.
    /// PUBREL has no topic and is forwarded unchanged.
    pub fn writeSessionTransmission(
        self: *Connection,
        transmission: @import("session/mod.zig").Transmission,
        maximum_qos: mqtt.QoS,
    ) Error!void {
        var visible = transmission;
        switch (visible) {
            .publish => |*publish_value| {
                publish_value.topic = try self.visibleTopic(
                    publish_value.topic,
                );
                publish_value.qos = if (@intFromEnum(publish_value.qos) <
                    @intFromEnum(maximum_qos))
                    publish_value.qos
                else
                    maximum_qos;
                return self.writeSessionPublish(publish_value.*);
            },
            .pubrel => |pubrel| return self.writeSessionPubRel(pubrel),
        }
    }

    /// Write client-owned durable QoS state without changing its delivery
    /// semantics. Unlike broker fanout, reconnect replay must never silently
    /// downgrade a previously accepted QoS.
    pub fn writeClientSessionTransmission(
        self: *Connection,
        transmission: @import("session/mod.zig").Transmission,
    ) Error!void {
        return switch (transmission) {
            .publish => |publish_value| {
                if (@intFromEnum(publish_value.qos) >
                    @intFromEnum(self.capabilities.peer_maximum_qos))
                {
                    return error.InvalidQoS;
                }
                if (publish_value.retain and
                    !self.peerRetainAvailable())
                {
                    return error.InvalidProperty;
                }
                return self.writeSessionPublish(publish_value);
            },
            .pubrel => |pubrel| return self.writeSessionPubRel(pubrel),
        };
    }

    /// Validate a canonical QoS 1/2 Session PUBLISH without reserving runtime
    /// packet state, committing a Topic Alias, or writing transport bytes.
    /// Durable coordinators use this before staging a message in their Session
    /// Store. The canonical full-topic representation is intentionally checked
    /// against Maximum Packet Size so a snapshot never depends on one current
    /// connection's alias table to remain sendable.
    pub fn validateClientSessionPublish(
        self: *Connection,
        topic: []const u8,
        payload: []const u8,
        options: PublishOptions,
    ) Error!void {
        if (options.qos == .at_most_once) return error.InvalidQoS;
        try @import("session/mod.zig").validatePublishForSession(
            topic,
            payload,
            options.properties,
        );
        try self.validateOutgoingPublish(
            topic,
            options.qos,
            options.retain,
            options.properties,
        );
        self.write_scratch.clearRetainingCapacity();
        const lengths = try mqtt.writePublishPrefix(
            &self.write_scratch,
            self.allocator,
            self.protocol,
            topic,
            payload,
            .{
                .qos = options.qos,
                .retain = options.retain,
                .dup = false,
                .packet_id = 1,
                .properties = options.properties,
            },
        );
        try self.authentication.ensurePacketAllowed(.publish);
        if (lengths.total > self.peer_max_packet_size) {
            return error.OutgoingPacketTooLarge;
        }
    }

    fn writeSessionPublish(
        self: *Connection,
        value: @import("session/mod.zig").PublishTransmission,
    ) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        try self.validatePublishPropertyDirection(
            value.properties,
            .outgoing,
        );
        // A durable Session always owns a canonical Topic Name. An alias is a
        // projection of that value onto one Network Connection and must never
        // be accepted from restored or caller-constructed Session state.
        if (mqtt.topicAlias(value.properties) != null) {
            return error.InvalidProperty;
        }
        var property_stack: [write_property_staging_capacity]mqtt.Property =
            undefined;
        var property_list = try self.writePropertyList(
            &property_stack,
            std.math.add(usize, value.properties.len, 1) catch
                return error.OutOfMemory,
        );
        const properties = &property_list;
        if (self.protocol == .v5) {
            for (value.properties) |property| {
                if (property == .four_byte and
                    property.four_byte.id == .message_expiry_interval)
                {
                    const remaining = value.message_expiry_interval orelse
                        continue;
                    properties.appendAssumeCapacity(.{ .four_byte = .{
                        .id = .message_expiry_interval,
                        .value = remaining,
                    } });
                } else {
                    properties.appendAssumeCapacity(property);
                }
            }
        }
        const property_count_before_alias = properties.items.len;
        const outgoing_topic = try self.prepareAutomaticTopicAliasAssumeCapacity(
            value.topic,
            properties,
        );
        const automatic_alias_added =
            properties.items.len != property_count_before_alias;
        const write_options: mqtt.PublishWriteOptions = .{
            .qos = value.qos,
            .retain = value.retain,
            .dup = value.qos != .at_most_once and value.dup,
            .packet_id = if (value.qos == .at_most_once)
                null
            else
                value.packet_id,
            .properties = properties.items,
        };
        try self.validateOutgoingPublish(
            outgoing_topic,
            write_options.qos,
            write_options.retain,
            properties.items,
        );
        self.writeValidatedPublish(
            outgoing_topic,
            value.payload,
            write_options,
        ) catch |err| {
            if (err != error.OutgoingPacketTooLarge or
                !automatic_alias_added)
            {
                return err;
            }
            // An alias property can be larger than the Topic Name it replaces
            // for a very short topic. If automatic aliasing alone crosses
            // Maximum Packet Size, keep the Application Message deliverable
            // with its canonical topic and no connection-state mutation.
            properties.shrinkRetainingCapacity(property_count_before_alias);
            const fallback_options: mqtt.PublishWriteOptions = .{
                .qos = write_options.qos,
                .retain = write_options.retain,
                .dup = write_options.dup,
                .packet_id = write_options.packet_id,
                .properties = properties.items,
            };
            try self.validateOutgoingPublish(
                value.topic,
                fallback_options.qos,
                fallback_options.retain,
                fallback_options.properties,
            );
            return self.writeValidatedPublish(
                value.topic,
                value.payload,
                fallback_options,
            );
        };
    }

    fn validateOutgoingPublish(
        self: *Connection,
        topic: []const u8,
        qos: mqtt.QoS,
        retain: bool,
        properties: []const mqtt.Property,
    ) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        try self.validatePublishPropertyDirection(properties, .outgoing);
        if (@intFromEnum(qos) >
            @intFromEnum(self.capabilities.peer_maximum_qos))
        {
            return error.InvalidQoS;
        }
        if (retain and !self.peerRetainAvailable()) {
            return error.InvalidProperty;
        }
        try self.validateOutgoingTopicAlias(topic, properties);
    }

    fn writeValidatedPublish(
        self: *Connection,
        topic: []const u8,
        payload: []const u8,
        options: mqtt.PublishWriteOptions,
    ) Error!void {
        self.write_scratch.clearRetainingCapacity();
        const lengths = try mqtt.writePublishPrefix(
            &self.write_scratch,
            self.allocator,
            self.protocol,
            topic,
            payload,
            options,
        );
        try self.authentication.ensurePacketAllowed(.publish);
        if (lengths.total > self.peer_max_packet_size) {
            return error.OutgoingPacketTooLarge;
        }
        // Topic-alias registration allocates connection-owned state. Complete
        // it after all local preflight checks but before any transport bytes
        // are emitted, so rejected packets cannot mutate the alias table and
        // OOM cannot be reported after the peer has received the packet.
        try self.prepareOutgoingTopicAliasCommit(
            topic,
            options.properties,
        );
        try self.writeTransportPacketParts(
            self.write_scratch.items,
            payload,
        );
        self.recordPacketSent(lengths.total);
    }

    pub fn writeSessionPubRel(
        self: *Connection,
        pubrel: @import("session/mod.zig").PubRelTransmission,
    ) Error!void {
        try self.writePubRel(pubrel.packet_id, 0);
    }

    pub fn completePublish(self: *Connection, packet_id: u16, qos: mqtt.QoS) Error!void {
        switch (qos) {
            .at_most_once => return,
            .at_least_once => try self.completePublishPubAck(packet_id),
            .exactly_once => try self.completePublishQoS2(packet_id),
        }
    }

    pub fn completePublishPubAck(self: *Connection, packet_id: u16) Error!void {
        if (packet_id != 0 and !self.packet_identifiers.contains(
            packet_id,
            .outgoing_qos1,
        )) return error.UnexpectedPacket;
        var ack = try self.readPubAck();
        defer ack.deinit(self.allocator);
        if (packet_id != 0 and ack.ack.packet_id != packet_id) return error.UnexpectedPacket;
        if (!self.packet_identifiers.contains(
            ack.ack.packet_id,
            .outgoing_qos1,
        )) return error.UnexpectedPacket;
        self.releaseOutgoingPublish(ack.ack.packet_id, .at_least_once);
        if (!ack.ack.accepted()) return error.PublishRefused;
    }

    pub fn completePublishQoS2(self: *Connection, packet_id: u16) Error!void {
        const id = try self.completePublishPubRec(packet_id);
        try self.completePublishPubComp(id);
    }

    pub fn completePublishPubRec(self: *Connection, packet_id: u16) Error!u16 {
        if (packet_id != 0 and !self.packet_identifiers.contains(
            packet_id,
            .outgoing_qos2,
        )) return error.UnexpectedPacket;
        var pubrec = try self.readPubRec();
        defer pubrec.deinit(self.allocator);
        if (packet_id != 0 and pubrec.ack.packet_id != packet_id) return error.UnexpectedPacket;
        if (!self.packet_identifiers.contains(
            pubrec.ack.packet_id,
            .outgoing_qos2,
        )) return error.UnexpectedPacket;
        if (!pubrec.ack.accepted()) {
            self.releaseOutgoingPublish(pubrec.ack.packet_id, .exactly_once);
            return error.PublishRefused;
        }
        try self.writePubRel(pubrec.ack.packet_id, 0);
        std.debug.assert(self.packet_identifiers.transition(
            pubrec.ack.packet_id,
            .outgoing_qos2,
            .outgoing_qos2_pubrel,
        ));
        return pubrec.ack.packet_id;
    }

    pub fn completePublishPubComp(self: *Connection, packet_id: u16) Error!void {
        if (!self.packet_identifiers.contains(
            packet_id,
            .outgoing_qos2_pubrel,
        )) return error.UnexpectedPacket;
        var pubcomp = try self.readPubComp();
        defer pubcomp.deinit(self.allocator);
        if (pubcomp.ack.packet_id != packet_id) return error.UnexpectedPacket;
        self.releaseOutgoingPublish(packet_id, .exactly_once);
        if (!pubcomp.ack.accepted()) return error.PublishRefused;
    }

    pub fn readPublish(self: *Connection) Error!OwnedPublish {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .publish) return error.UnexpectedPacket;
        var publish_packet = try mqtt.Publish.parsePayload(
            self.allocator,
            self.protocol,
            packet.fixed.flags,
            packet.remainingBytes(),
        );
        errdefer publish_packet.deinit(self.allocator);
        try self.validateIncomingUtf8(publish_packet.topic);
        try self.validateIncomingProperties(publish_packet.properties);
        try self.commitIncomingPublish(&publish_packet);
        return .{ .packet = packet, .publish = publish_packet };
    }

    pub fn writePubAck(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacketNoProperties(.puback, packet_id, reason_code);
        self.completeIncomingPublish(.puback, packet_id);
    }

    /// Whether an inbound QoS PUBLISH with this Packet Identifier is awaiting
    /// its first acknowledgement on this Network Connection. Reconnect clients
    /// use this to reject stale manual-ACK requests without exposing the
    /// connection's identifier-state representation.
    pub fn hasPendingIncomingPublish(
        self: *const Connection,
        packet_id: u16,
        qos: mqtt.QoS,
    ) bool {
        if (packet_id == 0) return false;
        return switch (qos) {
            .at_most_once => false,
            .at_least_once => self.packet_identifiers.contains(
                packet_id,
                .incoming_qos1,
            ),
            .exactly_once => self.packet_identifiers.contains(
                packet_id,
                .incoming_qos2,
            ),
        };
    }

    /// Whether this Network Connection currently owns an outbound QoS
    /// transaction with the supplied Packet Identifier, at any stage. Broker
    /// event loops use this before applying an acknowledgement so an unknown
    /// identifier can be ignored without weakening wrong-stage validation.
    pub fn hasOutgoingPacketIdentifier(
        self: *const Connection,
        packet_id: u16,
    ) bool {
        return packet_id != 0 and
            self.packet_identifiers.containsOutgoing(packet_id);
    }

    pub fn readPubAck(self: *Connection) Error!OwnedAck {
        return self.readAck(.puback);
    }

    /// Apply a PUBACK that was parsed by `readBrokerEvent`.
    ///
    /// Broker readers must demultiplex inbound packets before knowing which
    /// typed operation to invoke. Keeping state mutation here preserves the
    /// same unsolicited/negative-ack checks as the synchronous client path.
    pub fn applyPubAck(
        self: *Connection,
        ack: mqtt.AckPacket,
    ) Error!void {
        if (ack.packet_type != .puback or
            !self.packet_identifiers.contains(
                ack.packet_id,
                .outgoing_qos1,
            ))
        {
            return error.UnexpectedPacket;
        }
        self.releaseOutgoingPublish(
            ack.packet_id,
            .at_least_once,
        );
        if (!ack.accepted()) return error.PublishRefused;
    }

    /// Apply a downstream PUBREC parsed by `readBrokerEvent` and advance the
    /// broker-side sender to PUBREL.
    ///
    /// The caller serializes this method with all other writes for the same
    /// connection. State moves to the PUBREL set only after the packet is
    /// written, so a transport error cannot leave a live connection claiming
    /// progress that never reached its peer.
    pub fn applyPubRec(
        self: *Connection,
        ack: mqtt.AckPacket,
    ) Error!void {
        if (ack.packet_type != .pubrec) {
            return error.UnexpectedPacket;
        }
        if (self.packet_identifiers.contains(
            ack.packet_id,
            .outgoing_qos2_pubrel,
        )) {
            // A repeated successful PUBREC means the peer did not observe the
            // prior PUBREL. Retransmit it without changing inflight accounting
            // or the already-advanced QoS 2 stage.
            if (!ack.accepted()) return error.UnexpectedPacket;
            try self.writePubRel(ack.packet_id, 0);
            return;
        }
        if (!self.packet_identifiers.contains(
            ack.packet_id,
            .outgoing_qos2,
        )) return error.UnexpectedPacket;
        if (!ack.accepted()) {
            self.releaseOutgoingPublish(
                ack.packet_id,
                .exactly_once,
            );
            return error.PublishRefused;
        }
        try self.writePubRel(ack.packet_id, 0);
        std.debug.assert(self.packet_identifiers.transition(
            ack.packet_id,
            .outgoing_qos2,
            .outgoing_qos2_pubrel,
        ));
    }

    /// Apply the final PUBCOMP of a broker-originated QoS 2 delivery.
    pub fn applyPubComp(
        self: *Connection,
        ack: mqtt.AckPacket,
    ) Error!void {
        if (ack.packet_type != .pubcomp or
            !self.packet_identifiers.contains(
                ack.packet_id,
                .outgoing_qos2_pubrel,
            ))
        {
            return error.UnexpectedPacket;
        }
        self.releaseOutgoingPublish(
            ack.packet_id,
            .exactly_once,
        );
        if (!ack.accepted()) return error.PublishRefused;
    }

    pub fn writePubRec(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacketNoProperties(.pubrec, packet_id, reason_code);
        self.completeIncomingPubRec(packet_id, reason_code);
    }

    pub fn readPubRec(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubrec);
    }

    pub fn writePubRel(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacketNoProperties(.pubrel, packet_id, reason_code);
    }

    /// Write a retransmitted MQTT 3.1 PUBREL with DUP set. Later protocol
    /// versions reject `dup=true` because their fixed-header pattern is 0x2.
    pub fn writePubRelWithDup(
        self: *Connection,
        packet_id: u16,
        reason_code: u8,
        dup: bool,
    ) Error!void {
        var encoded: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
        try self.writeGeneratedPacket(
            try mqtt.AckPacket.writeNoPropertiesIntoWithDup(
                &encoded,
                self.protocol,
                .pubrel,
                dup,
                packet_id,
                reason_code,
            ),
            .pubrel,
        );
    }

    pub fn readPubRel(self: *Connection) Error!OwnedAck {
        var pubrel = try self.readAck(.pubrel);
        errdefer pubrel.deinit(self.allocator);
        try self.validateIncomingPubRel(pubrel.ack.packet_id);
        return pubrel;
    }

    /// Parse PUBREL without connection-local receive-state validation.
    ///
    /// Persistent broker Sessions may resume directly in await-PUBCOMP state
    /// after reconnect, where the new transport's fresh state table cannot
    /// know the original Packet Identifier.
    pub fn readSessionPubRel(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubrel);
    }

    /// Restore connection-local receive accounting before acknowledging a
    /// PUBREL that belongs to a durable transaction completed on an earlier
    /// Network Connection. MQTT 3.1.1 and MQTT 5 do not encode PUBREL retry
    /// state in the fixed header, so the broker uses this only after its
    /// Session store identifies the retry.
    pub fn resumeIncomingQoS2(
        self: *Connection,
        packet_id: u16,
    ) Error!void {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (self.packet_identifiers.contains(packet_id, .incoming_qos1)) {
            return error.InvalidPacketIdentifier;
        }
        if (self.packet_identifiers.contains(packet_id, .incoming_qos2)) return;
        if (self.incoming_inflight >= self.max_incoming_inflight) {
            return error.ReceiveMaximumExceeded;
        }
        _ = try self.packet_identifiers.add(
            self.allocator,
            packet_id,
            .incoming_qos2,
        );
        self.incoming_inflight += 1;
    }

    pub fn writePubComp(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacketNoProperties(.pubcomp, packet_id, reason_code);
        self.completeIncomingPublish(.pubcomp, packet_id);
    }

    pub fn readPubComp(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubcomp);
    }

    pub fn writePubAckWithProperties(self: *Connection, packet_id: u16, reason_code: u8, properties: []const mqtt.Property) Error!void {
        try self.writeAckPacket(.puback, packet_id, reason_code, properties);
        self.completeIncomingPublish(.puback, packet_id);
    }

    pub fn writePubRecWithProperties(self: *Connection, packet_id: u16, reason_code: u8, properties: []const mqtt.Property) Error!void {
        try self.writeAckPacket(.pubrec, packet_id, reason_code, properties);
        self.completeIncomingPubRec(packet_id, reason_code);
    }

    pub fn writePubRelWithProperties(self: *Connection, packet_id: u16, reason_code: u8, properties: []const mqtt.Property) Error!void {
        try self.writeAckPacket(.pubrel, packet_id, reason_code, properties);
    }

    pub fn writePubCompWithProperties(self: *Connection, packet_id: u16, reason_code: u8, properties: []const mqtt.Property) Error!void {
        try self.writeAckPacket(.pubcomp, packet_id, reason_code, properties);
        self.completeIncomingPublish(.pubcomp, packet_id);
    }

    fn writeAckPacketNoProperties(
        self: *Connection,
        packet_type: mqtt.PacketType,
        packet_id: u16,
        reason_code: u8,
    ) Error!void {
        var encoded: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
        try self.writeGeneratedPacket(try mqtt.AckPacket.writeNoPropertiesInto(
            &encoded,
            self.protocol,
            packet_type,
            packet_id,
            reason_code,
        ), packet_type);
    }

    fn writeAckPacket(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16, reason_code: u8, properties: []const mqtt.Property) Error!void {
        var property_stack: [write_property_staging_capacity]mqtt.Property =
            undefined;
        const outgoing_properties = try self.outgoingProblemProperties(
            &property_stack,
            packet_type,
            properties,
        );
        // Request Problem Information can remove every caller-supplied
        // diagnostic property. Route that result through the same bounded
        // encoder as the ordinary ACK methods instead of allocating an empty
        // general-purpose output buffer.
        if (outgoing_properties.len == 0) {
            return self.writeAckPacketNoProperties(
                packet_type,
                packet_id,
                reason_code,
            );
        }
        self.write_scratch.clearRetainingCapacity();
        try mqtt.AckPacket.write(
            &self.write_scratch,
            self.allocator,
            self.protocol,
            packet_type,
            packet_id,
            reason_code,
            outgoing_properties,
        );
        try self.writeGeneratedPacket(self.write_scratch.items, packet_type);
    }

    pub fn subscribe(self: *Connection, subscriptions: []const mqtt.Subscription, options: SubscribeOptions) Error!OwnedSubAck {
        try self.validateOutgoingPacketType(.subscribe);
        try self.validateOutgoingSubscribe(subscriptions, options.properties);
        try self.ensurePendingPacketQueueAvailable();
        const packet_id = self.nextPacketId();
        self.write_scratch.clearRetainingCapacity();
        try mqtt.Subscribe.write(&self.write_scratch, self.allocator, self.protocol, packet_id, options.properties, subscriptions);
        try self.writeGeneratedPacket(self.write_scratch.items, .subscribe);

        var suback = try self.finishReadSubAck(try AckReader.read(self, .suback, null));
        errdefer suback.deinit(self.allocator);
        if (suback.suback.packet_id != packet_id or suback.suback.reason_codes.len != subscriptions.len) {
            return error.UnexpectedPacket;
        }
        return suback;
    }

    pub fn readSubscribe(self: *Connection) Error!OwnedSubscribe {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .subscribe) return error.UnexpectedPacket;
        var subscribe_packet = try mqtt.Subscribe.parse(self.allocator, self.protocol, packet.bytes);
        errdefer subscribe_packet.deinit(self.allocator);
        try self.validateIncomingSubscriptionsUtf8(
            subscribe_packet.subscriptions,
        );
        try self.validateIncomingProperties(subscribe_packet.properties);
        try self.validateIncomingSubscribe(subscribe_packet.subscriptions, subscribe_packet.properties);
        return .{ .packet = packet, .subscribe = subscribe_packet };
    }

    pub fn writeSubAck(self: *Connection, packet_id: u16, reason_codes: []const u8, properties: []const mqtt.Property) Error!void {
        try self.validateOutgoingPacketType(.suback);
        var property_stack: [write_property_staging_capacity]mqtt.Property =
            undefined;
        const outgoing_properties = try self.outgoingProblemProperties(
            &property_stack,
            .suback,
            properties,
        );
        self.write_scratch.clearRetainingCapacity();
        if (outgoing_properties.len == 0) {
            const required = try mqtt.SubAck.noPropertiesWireLen(
                self.protocol,
                packet_id,
                reason_codes,
            );
            try self.write_scratch.resize(self.allocator, required);
            const encoded = try mqtt.SubAck.writeNoPropertiesInto(
                self.write_scratch.items,
                self.protocol,
                packet_id,
                reason_codes,
            );
            self.write_scratch.shrinkRetainingCapacity(encoded.len);
        } else {
            try mqtt.SubAck.write(
                &self.write_scratch,
                self.allocator,
                self.protocol,
                packet_id,
                outgoing_properties,
                reason_codes,
            );
        }
        try self.writeGeneratedPacket(self.write_scratch.items, .suback);
    }

    pub fn readSubAck(self: *Connection) Error!OwnedSubAck {
        return self.finishReadSubAck(try self.readPacket());
    }

    fn finishReadSubAck(self: *Connection, packet_value: OwnedPacket) Error!OwnedSubAck {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .suback) return error.UnexpectedPacket;
        var suback = try mqtt.SubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer suback.deinit(self.allocator);
        try self.validateIncomingProperties(suback.properties);
        return .{ .packet = packet, .suback = suback };
    }

    pub fn unsubscribe(self: *Connection, topic_filters: []const []const u8, options: UnsubscribeOptions) Error!OwnedUnsubAck {
        try self.validateOutgoingPacketType(.unsubscribe);
        const packet_id = self.nextPacketId();
        self.write_scratch.clearRetainingCapacity();
        try mqtt.Unsubscribe.write(&self.write_scratch, self.allocator, self.protocol, packet_id, options.properties, topic_filters);
        try self.ensurePendingPacketQueueAvailable();
        try self.writeGeneratedPacket(self.write_scratch.items, .unsubscribe);

        var unsuback = try self.finishReadUnsubAck(try AckReader.read(self, .unsuback, null));
        errdefer unsuback.deinit(self.allocator);
        try validateUnsubAckResponse(
            self.protocol,
            unsuback.unsuback,
            packet_id,
            topic_filters.len,
        );
        return unsuback;
    }

    pub fn readUnsubscribe(self: *Connection) Error!OwnedUnsubscribe {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .unsubscribe) return error.UnexpectedPacket;
        var unsubscribe_packet = try mqtt.Unsubscribe.parse(self.allocator, self.protocol, packet.bytes);
        errdefer unsubscribe_packet.deinit(self.allocator);
        try self.validateIncomingTopicFiltersUtf8(
            unsubscribe_packet.topic_filters,
        );
        try self.validateIncomingProperties(unsubscribe_packet.properties);
        return .{ .packet = packet, .unsubscribe = unsubscribe_packet };
    }

    pub fn writeUnsubAck(self: *Connection, packet_id: u16, reason_codes: []const u8, properties: []const mqtt.Property) Error!void {
        try self.validateOutgoingPacketType(.unsuback);
        var property_stack: [write_property_staging_capacity]mqtt.Property =
            undefined;
        const outgoing_properties = try self.outgoingProblemProperties(
            &property_stack,
            .unsuback,
            properties,
        );
        self.write_scratch.clearRetainingCapacity();
        if (outgoing_properties.len == 0) {
            const required = try mqtt.UnsubAck.noPropertiesWireLen(
                self.protocol,
                packet_id,
                reason_codes,
            );
            try self.write_scratch.resize(self.allocator, required);
            const encoded = try mqtt.UnsubAck.writeNoPropertiesInto(
                self.write_scratch.items,
                self.protocol,
                packet_id,
                reason_codes,
            );
            self.write_scratch.shrinkRetainingCapacity(encoded.len);
        } else {
            try mqtt.UnsubAck.write(
                &self.write_scratch,
                self.allocator,
                self.protocol,
                packet_id,
                outgoing_properties,
                reason_codes,
            );
        }
        try self.writeGeneratedPacket(self.write_scratch.items, .unsuback);
    }

    pub fn readUnsubAck(self: *Connection) Error!OwnedUnsubAck {
        return self.finishReadUnsubAck(try self.readPacket());
    }

    fn finishReadUnsubAck(
        self: *Connection,
        packet_value: OwnedPacket,
    ) Error!OwnedUnsubAck {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .unsuback) return error.UnexpectedPacket;
        var unsuback = try mqtt.UnsubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer unsuback.deinit(self.allocator);
        try self.validateIncomingProperties(unsuback.properties);
        return .{ .packet = packet, .unsuback = unsuback };
    }

    pub fn ping(self: *Connection) Error!void {
        try self.ensurePendingPacketQueueAvailable();
        return self.pingInternal(null);
    }

    /// Send PINGREQ and require the complete PINGRESP within one absolute
    /// budget. The deadline is not renewed by partial MQTT bytes, WebSocket
    /// message boundaries, or transport-level Ping/Pong frames. This exposes
    /// the liveness failure that asynchronous clients such as rumqttc report
    /// when a previous PINGREQ remains unacknowledged, while keeping `ping` as
    /// the compatibility API for callers that intentionally block forever.
    pub fn pingWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.ensurePendingPacketQueueAvailable();
        return self.pingInternal(self.transport.deadlineFromNow(timeout));
    }

    /// Send PINGREQ and wait for PINGRESP until a caller-owned absolute
    /// deadline. Interleaved MQTT packets retain their original wire order.
    pub fn pingWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        try self.ensurePendingPacketQueueAvailable();
        return self.pingInternal(deadline);
    }

    fn pingInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        var encoded: [mqtt.ping_packet_len]u8 = undefined;
        const bytes = mqtt.writePingInto(&encoded, false);
        if (deadline) |absolute|
            try self.writeGeneratedPacketWithDeadline(bytes, .pingreq, absolute)
        else
            try self.writeGeneratedPacket(bytes, .pingreq);
        var packet = try AckReader.read(self, .pingresp, deadline);
        defer packet.deinit(self.allocator);
        try mqtt.validatePing(packet.bytes, true);
    }

    pub fn readPingReq(self: *Connection) Error!void {
        var packet = try self.readPacket();
        defer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .pingreq) return error.UnexpectedPacket;
        try mqtt.validatePing(packet.bytes, false);
    }

    pub fn writePingResp(self: *Connection) Error!void {
        try self.validateOutgoingPacketType(.pingresp);
        var encoded: [mqtt.ping_packet_len]u8 = undefined;
        try self.writeGeneratedPacket(
            mqtt.writePingInto(&encoded, true),
            .pingresp,
        );
    }

    /// Emit a PINGREQ without consuming the socket. Event-loop owners use
    /// this split operation so the same receive path can continue delivering
    /// application packets while it waits for PINGRESP.
    pub fn writePingReq(self: *Connection) Error!void {
        try self.validateOutgoingPacketType(.pingreq);
        var encoded: [mqtt.ping_packet_len]u8 = undefined;
        try self.writeGeneratedPacket(
            mqtt.writePingInto(&encoded, false),
            .pingreq,
        );
    }

    /// Drop connection-local acknowledgement bookkeeping while preserving all
    /// negotiated limits. Durable clients keep QoS state in their Session
    /// store instead, so every new Network Connection starts with empty wire
    /// inflight tables even when CONNACK reports Session Present.
    pub fn resetPacketIdentifiers(self: *Connection) void {
        self.next_packet_id = 1;
        self.outgoing_inflight = 0;
        self.incoming_inflight = 0;
        self.packet_identifiers.clearRetainingCapacity();
    }

    pub fn disconnect(self: *Connection, reason_code: u8) Error!void {
        try self.writeDisconnectWithProperties(reason_code, &.{});
    }

    pub fn writeDisconnectWithProperties(
        self: *Connection,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) Error!void {
        try self.validateOutgoingDisconnect(reason_code, properties);
        if (properties.len == 0) {
            var encoded: [mqtt.Disconnect.no_properties_max_len]u8 = undefined;
            return self.writeGeneratedPacket(
                try mqtt.Disconnect.writeNoPropertiesInto(
                    &encoded,
                    self.protocol,
                    reason_code,
                ),
                .disconnect,
            );
        }
        self.write_scratch.clearRetainingCapacity();
        try mqtt.Disconnect.write(
            &self.write_scratch,
            self.allocator,
            self.protocol,
            reason_code,
            properties,
        );
        try self.writeGeneratedPacket(self.write_scratch.items, .disconnect);
    }

    fn validateOutgoingDisconnect(
        self: *const Connection,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) Error!void {
        switch (self.endpoint_role) {
            .unestablished => {},
            .client => {
                try mqtt.validateDisconnectReasonForSender(
                    reason_code,
                    .client,
                );
                try mqtt.validateDisconnectSessionExpiry(
                    self.connect_session_expiry,
                    mqtt.sessionExpiryInterval(properties),
                );
            },
            .server => {
                try mqtt.validateDisconnectReasonForSender(
                    reason_code,
                    .server,
                );
                // MQTT-3.14.2-2: a Server MUST NOT send Session Expiry.
                if (mqtt.sessionExpiryInterval(properties) != null) {
                    return error.InvalidProperty;
                }
            },
        }
    }

    fn validateIncomingDisconnect(
        self: *const Connection,
        disconnect_packet: mqtt.Disconnect,
    ) Error!void {
        switch (self.endpoint_role) {
            .unestablished => {},
            .client => {
                try mqtt.validateDisconnectReasonForSender(
                    disconnect_packet.reason_code,
                    .server,
                );
                // MQTT-3.14.2-2: a Server MUST NOT send Session Expiry.
                if (mqtt.sessionExpiryInterval(
                    disconnect_packet.properties,
                ) != null) return error.InvalidProperty;
            },
            .server => {
                try mqtt.validateDisconnectReasonForSender(
                    disconnect_packet.reason_code,
                    .client,
                );
                try mqtt.validateDisconnectSessionExpiry(
                    self.connect_session_expiry,
                    mqtt.sessionExpiryInterval(
                        disconnect_packet.properties,
                    ),
                );
            },
        }
    }

    pub fn readDisconnect(self: *Connection) Error!OwnedDisconnect {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .disconnect) return error.UnexpectedPacket;
        const disconnect_packet = try self.parseIncomingDisconnect(
            packet.bytes,
        );
        return .{ .packet = packet, .disconnect = disconnect_packet };
    }

    fn parseIncomingDisconnect(
        self: *const Connection,
        packet: []const u8,
    ) Error!mqtt.Disconnect {
        var disconnect_packet = try mqtt.Disconnect.parse(
            self.allocator,
            self.protocol,
            packet,
        );
        errdefer disconnect_packet.deinit(self.allocator);
        try self.validateIncomingProperties(disconnect_packet.properties);
        try self.validateIncomingDisconnect(disconnect_packet);
        return disconnect_packet;
    }

    pub fn writeAuth(self: *Connection, reason_code: u8, properties: []const mqtt.Property) Error!void {
        return self.writeAuthMaybeBefore(reason_code, properties, null);
    }

    fn writeAuthWithDeadline(
        self: *Connection,
        reason_code: u8,
        properties: []const mqtt.Property,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        return self.writeAuthMaybeBefore(reason_code, properties, deadline);
    }

    fn writeAuthMaybeBefore(
        self: *Connection,
        reason_code: u8,
        properties: []const mqtt.Property,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        try self.validateOutgoingAuthReason(reason_code);
        var property_stack: [write_property_staging_capacity]mqtt.Property =
            undefined;
        const outgoing_properties = try self.outgoingProblemProperties(
            &property_stack,
            .auth,
            properties,
        );
        if (outgoing_properties.len == 0) {
            var encoded: [mqtt.Auth.no_properties_max_len]u8 = undefined;
            const bytes = try mqtt.Auth.writeNoPropertiesInto(
                &encoded,
                self.protocol,
                reason_code,
            );
            return if (deadline) |absolute|
                self.writeGeneratedPacketWithDeadline(
                    bytes,
                    .auth,
                    absolute,
                )
            else
                self.writeGeneratedPacket(bytes, .auth);
        }
        self.write_scratch.clearRetainingCapacity();
        try mqtt.Auth.write(
            &self.write_scratch,
            self.allocator,
            self.protocol,
            reason_code,
            outgoing_properties,
        );
        if (deadline) |absolute|
            try self.writeGeneratedPacketWithDeadline(
                self.write_scratch.items,
                .auth,
                absolute,
            )
        else
            try self.writeGeneratedPacket(self.write_scratch.items, .auth);
    }

    fn validateOutgoingAuthReason(
        self: *const Connection,
        reason_code: u8,
    ) Error!void {
        switch (self.endpoint_role) {
            .unestablished => {},
            .client => try mqtt.validateAuthReasonForSender(
                reason_code,
                .client,
            ),
            .server => try mqtt.validateAuthReasonForSender(
                reason_code,
                .server,
            ),
        }
    }

    fn parseIncomingAuth(
        self: *const Connection,
        packet: []const u8,
    ) Error!mqtt.Auth {
        var auth = try mqtt.Auth.parse(
            self.allocator,
            self.protocol,
            packet,
        );
        errdefer auth.deinit(self.allocator);
        try self.validateIncomingProperties(auth.properties);
        switch (self.endpoint_role) {
            .unestablished => {},
            .client => try mqtt.validateAuthReasonForSender(
                auth.reason_code,
                .server,
            ),
            .server => try mqtt.validateAuthReasonForSender(
                auth.reason_code,
                .client,
            ),
        }
        return auth;
    }

    /// Apply the CONNECT Request Problem Information preference to outbound
    /// server packets. MQTT explicitly exempts PUBLISH, CONNACK and
    /// DISCONNECT; other packet types retain functional properties such as
    /// Authentication Method/Data while omitting diagnostic fields.
    fn outgoingProblemProperties(
        self: *Connection,
        stack: *[write_property_staging_capacity]mqtt.Property,
        packet_type: mqtt.PacketType,
        properties: []const mqtt.Property,
    ) Error![]const mqtt.Property {
        if (self.protocol != .v5 or
            self.capabilities.peer_requested_problem_information or
            packet_type == .publish or
            packet_type == .connack or
            packet_type == .disconnect)
        {
            return properties;
        }
        var retained_count: usize = 0;
        for (properties) |property| {
            retained_count += @intFromBool(
                !problemInformationProperty(property),
            );
        }
        if (retained_count == properties.len) return properties;
        if (retained_count == 0) return &.{};
        var filtered = try self.writePropertyList(stack, retained_count);
        for (properties) |property| {
            if (!problemInformationProperty(property)) {
                filtered.appendAssumeCapacity(property);
            }
        }
        return filtered.items;
    }

    /// Start MQTT 5 re-authentication with the CONNECT-negotiated method.
    pub fn beginReauthentication(
        self: *Connection,
        data: []const u8,
    ) Error!void {
        try self.validateOutgoingAuthReason(0x19);
        const method = self.authentication.method() orelse
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
        const previous_phase = self.authentication.phase;
        try self.authentication.beginReauthentication(
            &properties,
        );
        self.writeAuth(0x19, &properties) catch |err| {
            self.authentication.phase = previous_phase;
            return err;
        };
    }

    /// Start client-initiated MQTT 5 re-authentication with a complete AUTH
    /// property set. The negotiated Authentication Method is mandatory and is
    /// validated before the connection enters its traffic gate.
    pub fn beginReauthenticationWithProperties(
        self: *Connection,
        properties: []const mqtt.Property,
    ) Error!void {
        try self.validateOutgoingAuthReason(0x19);
        const previous_phase = self.authentication.phase;
        try self.authentication.beginReauthentication(properties);
        self.writeAuth(0x19, properties) catch |err| {
            self.authentication.phase = previous_phase;
            return err;
        };
    }

    /// Receive one re-authentication continuation/completion packet.
    pub fn receiveReauthentication(
        self: *Connection,
    ) Error!struct {
        auth: OwnedAuth,
        complete: bool,
    } {
        var auth = try self.readAuth();
        errdefer auth.deinit(self.allocator);
        const complete = try self.authentication.receiveReauth(
            auth.auth,
        );
        return .{ .auth = auth, .complete = complete };
    }

    /// Apply an AUTH packet returned by `readBrokerEvent`.
    ///
    /// A peer may start re-authentication while the broker event loop is
    /// multiplexing PUBLISH/ACK traffic. This method transitions Active to
    /// Reauthenticating for reason 0x19, or advances an existing exchange.
    pub fn applyAuthenticationEvent(
        self: *Connection,
        auth: mqtt.Auth,
    ) Error!bool {
        if (auth.reason_code == 0x19) {
            self.authentication.beginReauthentication(
                auth.properties,
            ) catch |err| {
                if (err == error.AuthenticationMethodMismatch or
                    err == error.AuthenticationNotConfigured or
                    err == error.InvalidAuthenticationState)
                {
                    self.sendAuthenticationProtocolError();
                }
                return err;
            };
            return false;
        }
        return self.authentication.receiveReauth(auth) catch |err| {
            if (err == error.AuthenticationMethodMismatch or
                err == error.AuthenticationNotConfigured or
                err == error.InvalidAuthenticationState)
            {
                self.sendAuthenticationProtocolError();
            }
            return err;
        };
    }

    /// Continue a peer-initiated re-authentication exchange.
    pub fn continueReauthentication(
        self: *Connection,
        reason_code: u8,
        data: []const u8,
    ) Error!void {
        if (self.authentication.phase != .reauthenticating) {
            return error.InvalidAuthenticationState;
        }
        const method = self.authentication.method() orelse
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
        if (reason_code != 0 and reason_code != 0x18) {
            return error.InvalidAuthenticationState;
        }
        try self.writeAuth(reason_code, &properties);
        if (reason_code == 0) {
            try self.authentication.finishReauthentication();
        }
    }

    /// Continue a live re-authentication exchange with caller-provided MQTT 5
    /// properties. This is the event-loop counterpart to the data-only helper
    /// above and preserves User Properties or method-specific metadata emitted
    /// by the same callback used during initial CONNECT authentication.
    pub fn continueReauthenticationWithProperties(
        self: *Connection,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.authentication.phase != .reauthenticating) {
            return error.InvalidAuthenticationState;
        }
        if (reason_code != 0 and reason_code != 0x18) {
            return error.InvalidAuthenticationState;
        }
        try self.authentication.validatePeerProperties(properties);
        try self.writeAuth(reason_code, properties);
        if (reason_code == 0) {
            try self.authentication.finishReauthentication();
        }
    }

    /// Reject peer-initiated re-authentication and retire this Network
    /// Connection after the failure DISCONNECT has been written.
    pub fn rejectReauthentication(
        self: *Connection,
        reason_code: u8,
    ) Error!void {
        try self.rejectReauthenticationWithProperties(reason_code, &.{});
    }

    /// Property-capable counterpart to `rejectReauthentication`. The caller
    /// retains Connection ownership and must eventually call `close`, but all
    /// intervening MQTT operations fail with `error.ConnectionClosed`.
    pub fn rejectReauthenticationWithProperties(
        self: *Connection,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.authentication.phase != .reauthenticating or
            reason_code == 0)
        {
            return error.InvalidAuthenticationState;
        }
        try self.writeDisconnectWithProperties(reason_code, properties);
        self.transport_unusable.store(true, .release);
    }

    /// Respond to an initial pre-CONNACK authentication challenge.
    pub fn continueInitialAuthentication(
        self: *Connection,
        data: []const u8,
    ) Error!void {
        if (self.authentication.phase != .authenticating) {
            return error.InvalidAuthenticationState;
        }
        const method = self.authentication.method() orelse
            return error.AuthenticationNotConfigured;
        try self.writeAuth(0x18, &.{
            .{ .utf8 = .{
                .id = .authentication_method,
                .value = method,
            } },
            .{ .binary = .{
                .id = .authentication_data,
                .value = data,
            } },
        });
    }

    /// Accept a peer's Re-authenticate request and enter the traffic gate.
    pub fn acceptReauthentication(
        self: *Connection,
    ) Error!OwnedAuth {
        var auth = try self.readAuth();
        errdefer auth.deinit(self.allocator);
        if (auth.auth.reason_code != 0x19) {
            self.sendAuthenticationProtocolError();
            return error.InvalidAuthenticationState;
        }
        self.authentication.beginReauthentication(
            auth.auth.properties,
        ) catch |err| {
            if (err == error.AuthenticationMethodMismatch) {
                self.sendAuthenticationProtocolError();
            }
            return err;
        };
        return auth;
    }

    pub fn readAuth(self: *Connection) Error!OwnedAuth {
        return self.readAuthMaybeBefore(null);
    }

    pub fn readAuthWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedAuth {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readAuthWithDeadline(self.transport.deadlineFromNow(timeout));
    }

    pub fn readAuthWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedAuth {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        return self.readAuthMaybeBefore(deadline);
    }

    fn readAuthMaybeBefore(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedAuth {
        var packet = if (deadline) |absolute|
            try self.readPacketWithDeadline(absolute)
        else
            try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .auth) return error.UnexpectedPacket;
        const auth_packet = try self.parseIncomingAuth(packet.bytes);
        return .{ .packet = packet, .auth = auth_packet };
    }

    /// Read one broker-facing packet while preserving transport-independent
    /// connection validation and inflight state.
    pub fn readBrokerEvent(self: *Connection) Error!BrokerEvent {
        return self.readBrokerEventInternal(null);
    }

    /// Read one broker-facing event while allowing a complete short TCP
    /// packet to borrow `storage` until the returned event is deinitialized.
    /// TLS and WebSocket transports retain their ordinary owned behavior.
    /// Callers must not reuse `storage` before `BrokerEvent.deinit`.
    pub fn readBrokerEventInto(
        self: *Connection,
        storage: []u8,
    ) Error!BrokerEvent {
        return self.readBrokerEventInternalInto(null, storage);
    }

    /// Read one broker-facing event within a relative application budget.
    /// The resulting absolute deadline covers the complete MQTT packet and is
    /// not renewed when the peer trickles a fixed header or payload.
    pub fn readBrokerEventWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!BrokerEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readBrokerEventWithDeadline(
            self.transport.deadlineFromNow(timeout),
        );
    }

    /// Read one broker-facing event under an absolute application deadline.
    /// Unlike Keep Alive enforcement, progress on a large packet does not
    /// renew this caller-owned budget.
    pub fn readBrokerEventWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!BrokerEvent {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        var packet = try self.readPacketWithDeadline(deadline);
        errdefer packet.deinit(self.allocator);
        return self.finishBrokerEvent(packet);
    }

    /// Read one packet valid on an established client connection. Unlike the
    /// synchronous typed helpers, this preserves packet ordering while a
    /// single owner multiplexes publications, QoS acknowledgements, liveness,
    /// server DISCONNECT, and enhanced authentication.
    pub fn readClientPacketEvent(
        self: *Connection,
    ) Error!ClientPacketEvent {
        return self.finishClientPacketEvent(try self.readPacket());
    }

    /// Bounded variant of `readClientPacketEvent`. One absolute deadline
    /// covers the complete Control Packet, so a peer cannot defeat a caller's
    /// poll budget by trickling the packet header or body.
    pub fn readClientPacketEventWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!ClientPacketEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = self.transport.deadlineFromNow(timeout);
        const packet = if (self.popPendingPacket()) |pending|
            pending
        else
            try self.readTransportPacketWithDeadline(deadline);
        return self.finishClientPacketEvent(packet);
    }

    /// Absolute-deadline counterpart for event loops that share one budget
    /// across MQTT operations. Already queued packets are returned first.
    pub fn readClientPacketEventWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ClientPacketEvent {
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        const packet = if (self.popPendingPacket()) |pending|
            pending
        else
            try self.readTransportPacketWithDeadline(deadline);
        return self.finishClientPacketEvent(packet);
    }

    fn finishClientPacketEvent(
        self: *Connection,
        packet_value: OwnedPacket,
    ) Error!ClientPacketEvent {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        return switch (packet.fixed.packet_type) {
            .auth => blk: {
                const value = try self.parseIncomingAuth(
                    packet.bytes,
                );
                break :blk .{ .auth = .{
                    .packet = packet,
                    .auth = value,
                } };
            },
            .publish => blk: {
                var value = try mqtt.Publish.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingUtf8(value.topic);
                try self.validateIncomingProperties(value.properties);
                try self.commitIncomingPublish(&value);
                break :blk .{ .publish = .{
                    .packet = packet,
                    .publish = value,
                } };
            },
            .puback, .pubrec, .pubrel, .pubcomp => |packet_type| blk: {
                var value = try mqtt.AckPacket.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.packet_type,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingProperties(value.properties);
                const owned = OwnedAck{ .packet = packet, .ack = value };
                break :blk switch (packet_type) {
                    .puback => .{ .puback = owned },
                    .pubrec => .{ .pubrec = owned },
                    // Durable reconnect clients validate PUBREL against their
                    // Session store, not this transport's fresh state table.
                    .pubrel => .{ .pubrel = owned },
                    .pubcomp => .{ .pubcomp = owned },
                    else => unreachable,
                };
            },
            .pingresp => blk: {
                try mqtt.validatePing(packet.bytes, true);
                break :blk .{ .pingresp = packet };
            },
            .disconnect => blk: {
                const value = try self.parseIncomingDisconnect(
                    packet.bytes,
                );
                break :blk .{ .disconnect = .{
                    .packet = packet,
                    .disconnect = value,
                } };
            },
            else => error.UnexpectedPacket,
        };
    }

    /// Read one broker event with MQTT Keep Alive inactivity enforcement.
    ///
    /// A CONNECT Keep Alive of zero disables this timeout. Otherwise the
    /// Server must close the Network Connection after one-and-a-half times the
    /// negotiated interval without a complete packet. The transport mirrors
    /// Mosquitto's large-packet progress exception while keeping one deadline
    /// across ordinary packet fragments.
    pub fn readBrokerEventWithKeepAlive(
        self: *Connection,
    ) Error!BrokerEvent {
        return self.readBrokerEventInternal(
            keepAliveTimeout(self.keep_alive_seconds),
        );
    }

    /// Keep-Alive-bounded counterpart to `readBrokerEventInto`.
    pub fn readBrokerEventWithKeepAliveInto(
        self: *Connection,
        storage: []u8,
    ) Error!BrokerEvent {
        return self.readBrokerEventInternalInto(
            keepAliveTimeout(self.keep_alive_seconds),
            storage,
        );
    }

    /// Broker hot-path variant that reserves an aligned prefix when a TCP
    /// packet is too large for `storage`. The returned event keeps ownership
    /// unless a longer-lived broker object explicitly adopts that allocation.
    pub fn readBrokerEventWithKeepAliveIntoPrefixed(
        self: *Connection,
        storage: []u8,
        prefix_len: usize,
    ) Error!BrokerEvent {
        var event: BrokerEvent = undefined;
        try self.readBrokerEventWithKeepAliveIntoPrefixedOut(
            storage,
            prefix_len,
            &event,
        );
        return event;
    }

    /// Caller-output form for broker loops that retain one event slot across
    /// iterations and want to avoid returning the large tagged union by value.
    /// On success, ownership is transferred through `out` and the caller must
    /// call `BrokerEvent.deinit`. On error, `out` is left untouched.
    pub fn readBrokerEventWithKeepAliveIntoPrefixedOut(
        self: *Connection,
        storage: []u8,
        prefix_len: usize,
        out: *BrokerEvent,
    ) Error!void {
        const timeout = keepAliveTimeout(self.keep_alive_seconds);
        var packet = if (timeout) |value|
            try self.transport
                .readPacketWithInactivityTimeoutIntoWithPrefix(
                self.allocator,
                self.limits.max_packet_size,
                value,
                storage,
                prefix_len,
            )
        else
            try self.transport.readPacketIntoWithPrefix(
                self.allocator,
                self.limits.max_packet_size,
                storage,
                prefix_len,
            );
        errdefer packet.deinit(self.allocator);
        self.recordPacketReceived(packet.bytes.len);
        try self.validateReadPacket(&packet);
        try self.finishBrokerEventInto(packet, out);
    }

    fn readBrokerEventInternal(
        self: *Connection,
        inactivity_timeout: ?std.Io.Clock.Duration,
    ) Error!BrokerEvent {
        var packet = if (inactivity_timeout) |timeout|
            try self.readPacketWithInactivityTimeout(timeout)
        else
            try self.readPacket();
        errdefer packet.deinit(self.allocator);
        return self.finishBrokerEvent(packet);
    }

    fn readBrokerEventInternalInto(
        self: *Connection,
        inactivity_timeout: ?std.Io.Clock.Duration,
        storage: []u8,
    ) Error!BrokerEvent {
        var packet = if (inactivity_timeout) |timeout|
            try self.readPacketWithInactivityTimeoutInto(timeout, storage)
        else
            try self.readPacketInto(storage);
        errdefer packet.deinit(self.allocator);
        return self.finishBrokerEvent(packet);
    }

    fn finishBrokerEvent(
        self: *Connection,
        packet: OwnedPacket,
    ) Error!BrokerEvent {
        var event: BrokerEvent = undefined;
        try self.finishBrokerEventInto(packet, &event);
        return event;
    }

    fn finishBrokerEventInto(
        self: *Connection,
        packet: OwnedPacket,
        out: *BrokerEvent,
    ) Error!void {
        switch (packet.fixed.packet_type) {
            .auth => {
                const value = try self.parseIncomingAuth(
                    packet.bytes,
                );
                out.* = .{ .auth = .{
                    .packet = packet,
                    .auth = value,
                } };
            },
            .publish => {
                var value = try mqtt.Publish.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingUtf8(value.topic);
                try self.validateIncomingProperties(value.properties);
                try self.commitIncomingPublish(&value);
                out.* = .{ .publish = .{
                    .packet = packet,
                    .publish = value,
                } };
            },
            .subscribe => {
                var value = try mqtt.Subscribe.parse(
                    self.allocator,
                    self.protocol,
                    packet.bytes,
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingSubscriptionsUtf8(
                    value.subscriptions,
                );
                try self.validateIncomingProperties(value.properties);
                try self.validateIncomingSubscribe(
                    value.subscriptions,
                    value.properties,
                );
                out.* = .{ .subscribe = .{
                    .packet = packet,
                    .subscribe = value,
                } };
            },
            .unsubscribe => {
                var value = try mqtt.Unsubscribe.parse(
                    self.allocator,
                    self.protocol,
                    packet.bytes,
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingTopicFiltersUtf8(
                    value.topic_filters,
                );
                try self.validateIncomingProperties(value.properties);
                out.* = .{ .unsubscribe = .{
                    .packet = packet,
                    .unsubscribe = value,
                } };
            },
            .puback => {
                var value = try mqtt.AckPacket.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.packet_type,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingProperties(value.properties);
                out.* = .{ .puback = .{
                    .packet = packet,
                    .ack = value,
                } };
            },
            .pubrec => {
                var value = try mqtt.AckPacket.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.packet_type,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingProperties(value.properties);
                out.* = .{ .pubrec = .{
                    .packet = packet,
                    .ack = value,
                } };
            },
            .pubrel => {
                var value = try mqtt.AckPacket.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.packet_type,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingProperties(value.properties);
                // Unlike the strict synchronous `readPubRel`, a broker must
                // see unknown/repeated identifiers so it can answer PUBCOMP
                // 0x92 rather than converting an idempotent control packet
                // into an immediate transport failure.
                out.* = .{ .pubrel = .{
                    .packet = packet,
                    .ack = value,
                } };
            },
            .pubcomp => {
                var value = try mqtt.AckPacket.parsePayload(
                    self.allocator,
                    self.protocol,
                    packet.fixed.packet_type,
                    packet.fixed.flags,
                    packet.remainingBytes(),
                );
                errdefer value.deinit(self.allocator);
                try self.validateIncomingProperties(value.properties);
                out.* = .{ .pubcomp = .{
                    .packet = packet,
                    .ack = value,
                } };
            },
            .pingreq => {
                try mqtt.validatePing(packet.bytes, false);
                out.* = .{ .pingreq = packet };
            },
            .disconnect => {
                const value = try self.parseIncomingDisconnect(
                    packet.bytes,
                );
                out.* = .{ .disconnect = .{
                    .packet = packet,
                    .disconnect = value,
                } };
            },
            else => return error.UnexpectedPacket,
        }
    }

    fn validateOutgoingTopicAlias(self: *Connection, topic: []const u8, properties: []const mqtt.Property) Error!void {
        const alias = mqtt.topicAlias(properties) orelse return;
        if (alias == 0 or alias > self.peer_topic_alias_maximum) {
            return error.InvalidProperty;
        }
        if (topic.len == 0 and
            self.outgoingTopicAlias(alias) == null)
        {
            return error.InvalidTopic;
        }
    }

    fn prepareOutgoingTopicAliasCommit(
        self: *Connection,
        topic: []const u8,
        properties: []const mqtt.Property,
    ) Error!void {
        const alias = mqtt.topicAlias(properties) orelse return;
        if (topic.len == 0) return;
        const newly_allocated = self.outgoing_topic_aliases == null;
        const aliases = try self.ensureOutgoingTopicAliases();
        errdefer if (newly_allocated) {
            self.clearOutgoingTopicAliases();
        };
        try aliases.put(
            self.allocator,
            alias,
            topic,
        );
    }

    fn applyIncomingTopicAlias(
        self: *Connection,
        publish_packet: *mqtt.Publish,
    ) Error!void {
        try self.validateIncomingTopicAlias(publish_packet.*);
        return self.applyValidatedIncomingTopicAlias(publish_packet);
    }

    fn applyValidatedIncomingTopicAlias(
        self: *Connection,
        publish_packet: *mqtt.Publish,
    ) Error!void {
        const alias = mqtt.topicAlias(publish_packet.properties) orelse {
            return;
        };
        if (publish_packet.topic.len != 0) {
            const newly_allocated = self.incoming_topic_aliases == null;
            const aliases = try self.ensureIncomingTopicAliases();
            errdefer if (newly_allocated) {
                self.clearIncomingTopicAliases();
            };
            try aliases.put(
                self.allocator,
                alias,
                publish_packet.topic,
            );
            return;
        }
        const stored = self.incomingTopicAlias(alias) orelse
            return error.InvalidTopic;
        publish_packet.topic = stored;
    }

    fn validateIncomingTopicAlias(
        self: Connection,
        publish_packet: mqtt.Publish,
    ) Error!void {
        const alias = mqtt.topicAlias(publish_packet.properties) orelse {
            try mqtt.validateTopicName(publish_packet.topic);
            return;
        };
        if (alias == 0 or alias > self.incoming_topic_alias_maximum) {
            return error.TopicAliasInvalid;
        }
        if (publish_packet.topic.len != 0) {
            try mqtt.validateTopicName(publish_packet.topic);
            return;
        }
        if (self.incomingTopicAlias(alias) == null) {
            return error.InvalidTopic;
        }
    }

    fn commitIncomingPublish(
        self: *Connection,
        publish_packet: *mqtt.Publish,
    ) Error!void {
        try self.validateIncomingPublishCapabilities(publish_packet.*);
        try self.validateIncomingTopicAlias(publish_packet.*);
        const recorded = try self.recordIncomingPublish(publish_packet.*);
        errdefer if (recorded) {
            const packet_id = publish_packet.packet_id.?;
            const stage: packet_identifiers.State.Stage = switch (publish_packet.qos) {
                .at_most_once => unreachable,
                .at_least_once => .incoming_qos1,
                .exactly_once => .incoming_qos2,
            };
            std.debug.assert(self.packet_identifiers.remove(packet_id, stage));
            self.incoming_inflight -= 1;
        };
        try self.applyValidatedIncomingTopicAlias(publish_packet);
    }

    fn validateIncomingPublishCapabilities(self: Connection, publish_packet: mqtt.Publish) Error!void {
        try self.validatePublishPropertyDirection(
            publish_packet.properties,
            .incoming,
        );
        // Keep negotiated-capability failures distinct from malformed wire
        // values. The broker can then send the precise MQTT 5 DISCONNECT
        // reason without accidentally classifying every codec InvalidQoS or
        // InvalidProperty failure as an unsupported feature.
        if (@intFromEnum(publish_packet.qos) >
            @intFromEnum(self.capabilities.local_maximum_qos))
        {
            return error.QoSNotSupported;
        }
        if (publish_packet.retain and
            !self.capabilities.local_retain_available)
        {
            return error.RetainNotSupported;
        }
    }

    fn validateIncomingConnectUtf8(
        self: Connection,
        connect: mqtt.Connect,
    ) Error!void {
        if (!self.strict_utf8) return;
        try mqtt.validateStrictUtf8String(connect.client_id);
        try mqtt.validateStrictUtf8Properties(connect.properties);
        if (connect.username) |username| {
            try mqtt.validateStrictUtf8String(username);
        }
        if (connect.will) |will| {
            try mqtt.validateStrictUtf8String(will.topic);
            try mqtt.validateStrictUtf8Properties(will.properties);
        }
    }

    fn validateIncomingUtf8(
        self: Connection,
        value: []const u8,
    ) Error!void {
        if (self.strict_utf8) try mqtt.validateStrictUtf8String(value);
    }

    fn validateIncomingProperties(
        self: Connection,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.strict_utf8) {
            try mqtt.validateStrictUtf8Properties(properties);
        }
    }

    fn validateIncomingSubscriptionsUtf8(
        self: Connection,
        subscriptions: []const mqtt.Subscription,
    ) Error!void {
        if (!self.strict_utf8) return;
        for (subscriptions) |subscription| {
            try mqtt.validateStrictUtf8String(subscription.topic_filter);
        }
    }

    fn validateIncomingTopicFiltersUtf8(
        self: Connection,
        topic_filters: []const []const u8,
    ) Error!void {
        if (!self.strict_utf8) return;
        for (topic_filters) |filter| {
            try mqtt.validateStrictUtf8String(filter);
        }
    }

    const PublishDirection = enum { incoming, outgoing };

    fn validatePublishPropertyDirection(
        self: Connection,
        properties: []const mqtt.Property,
        direction: PublishDirection,
    ) Error!void {
        if (self.protocol != .v5 or
            mqtt.subscriptionIdentifier(properties) == null) return;
        const sender_is_client = switch (direction) {
            .incoming => self.endpoint_role == .server,
            .outgoing => self.endpoint_role == .client,
        };
        if (sender_is_client) return error.InvalidProperty;
    }

    fn validateIncomingPubRel(self: Connection, packet_id: u16) Error!void {
        // A PUBREL is valid only after this endpoint has received a QoS 2
        // PUBLISH with the same Packet Identifier and answered PUBREC.  Rumqtt
        // treats an unsolicited PUBREL as a state error; preserve that guard so
        // peer bugs cannot complete or disturb unrelated QoS state.
        if (!self.packet_identifiers.contains(
            packet_id,
            .incoming_qos2,
        )) return error.InvalidPacketIdentifier;
    }

    fn recordIncomingPublish(self: *Connection, publish_packet: mqtt.Publish) Error!bool {
        const packet_id = publish_packet.packet_id orelse return false;
        const stage: packet_identifiers.State.Stage = switch (publish_packet.qos) {
            .at_most_once => return false,
            .at_least_once => .incoming_qos1,
            .exactly_once => .incoming_qos2,
        };
        const other_stage: packet_identifiers.State.Stage = switch (publish_packet.qos) {
            .at_most_once => unreachable,
            .at_least_once => .incoming_qos2,
            .exactly_once => .incoming_qos1,
        };

        if (self.packet_identifiers.contains(packet_id, other_stage)) {
            return error.InvalidPacketIdentifier;
        }
        // Retransmissions reuse the same Packet Identifier and must not consume
        // another Receive Maximum slot. Packet Identifier is the stable O(1)
        // lookup key, so a retry cannot grow memory or make the connection
        // look over quota.
        if (self.packet_identifiers.contains(packet_id, stage)) return false;
        if (self.incoming_inflight >= self.max_incoming_inflight) return error.ReceiveMaximumExceeded;
        _ = try self.packet_identifiers.add(
            self.allocator,
            packet_id,
            stage,
        );
        self.incoming_inflight += 1;
        return true;
    }

    fn completeIncomingPublish(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16) void {
        const stage: packet_identifiers.State.Stage = switch (packet_type) {
            .puback => .incoming_qos1,
            .pubcomp => .incoming_qos2,
            else => return,
        };
        if (!self.packet_identifiers.remove(packet_id, stage)) return;
        self.incoming_inflight -= 1;
    }

    fn completeIncomingPubRec(self: *Connection, packet_id: u16, reason_code: u8) void {
        // MQTT 5 negative PUBREC reason codes terminate the QoS 2 handshake:
        // the sender must not continue with PUBREL.  Release the receive slot
        // immediately, while success and "No matching subscribers" continue
        // through PUBREL/PUBCOMP like rumqtt's QoS2 state machine.
        if (reason_code >= 0x80) self.completeIncomingPublish(.pubcomp, packet_id);
    }

    fn validateOutgoingSubscribe(self: Connection, subscriptions: []const mqtt.Subscription, properties: []const mqtt.Property) Error!void {
        validateSubscribeCapabilities(
            subscriptions,
            properties,
            self.capabilities.peer_wildcard_subscription_available,
            self.capabilities.peer_subscription_identifier_available,
            self.capabilities.peer_shared_subscription_available,
        ) catch |err| switch (err) {
            error.WildcardSubscriptionsNotSupported,
            error.SubscriptionIdentifiersNotSupported,
            error.SharedSubscriptionsNotSupported,
            => return error.SubscriptionRefused,
        };
    }

    fn validateIncomingSubscribe(self: Connection, subscriptions: []const mqtt.Subscription, properties: []const mqtt.Property) Error!void {
        try validateSubscribeCapabilities(
            subscriptions,
            properties,
            self.capabilities.local_wildcard_subscription_available,
            self.capabilities.local_subscription_identifier_available,
            self.capabilities.local_shared_subscription_available,
        );
    }

    fn validateSubscribeCapabilities(
        subscriptions: []const mqtt.Subscription,
        properties: []const mqtt.Property,
        wildcard_available: bool,
        subscription_identifier_available: bool,
        shared_available: bool,
    ) error{
        WildcardSubscriptionsNotSupported,
        SubscriptionIdentifiersNotSupported,
        SharedSubscriptionsNotSupported,
    }!void {
        if (!subscription_identifier_available and
            mqtt.subscriptionIdentifier(properties) != null)
        {
            return error.SubscriptionIdentifiersNotSupported;
        }
        for (subscriptions) |subscription| {
            if (!shared_available and
                std.mem.startsWith(
                    u8,
                    subscription.topic_filter,
                    "$share/",
                ))
            {
                return error.SharedSubscriptionsNotSupported;
            }
            if (!wildcard_available and
                mqtt.hasWildcards(subscription.topic_filter))
            {
                return error.WildcardSubscriptionsNotSupported;
            }
        }
    }

    fn writePacket(self: *Connection, bytes: []u8) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        const fixed = try mqtt.FixedHeader.parse(bytes);
        try mqtt.validatePacketFlags(self.protocol, fixed);
        try self.validatePacketForWrite(fixed.packet_type, bytes.len);
        try self.writeTransportPacket(bytes);
        self.recordPacketSent(bytes.len);
    }

    /// Write bytes produced by the matching MQTT encoder without reparsing
    /// their Fixed Header. Raw or restored packet bytes must use `writePacket`.
    fn writeGeneratedPacket(
        self: *Connection,
        bytes: []u8,
        packet_type: mqtt.PacketType,
    ) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        try self.validatePacketForWrite(packet_type, bytes.len);
        try self.writeTransportPacket(bytes);
        self.recordPacketSent(bytes.len);
    }

    /// Deadline-bounded counterpart for bytes produced by a matching MQTT
    /// encoder. It does not parse the already known Fixed Header again.
    fn writeGeneratedPacketWithDeadline(
        self: *Connection,
        bytes: []u8,
        packet_type: mqtt.PacketType,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        _ = try deadline_policy.usableAwake(
            self.transport.ioHandle(),
            deadline,
        );
        try self.validatePacketForWrite(packet_type, bytes.len);
        self.transport.writePacketWithDeadline(bytes, deadline) catch |err| {
            self.transport_unusable.store(true, .release);
            return err;
        };
        self.recordPacketSent(bytes.len);
    }

    fn validatePacketForWrite(
        self: *const Connection,
        packet_type: mqtt.PacketType,
        packet_len: usize,
    ) Error!void {
        try self.validateOutgoingPacketType(packet_type);
        try self.authentication.ensurePacketAllowed(packet_type);
        if (packet_len > self.peer_max_packet_size) {
            return error.OutgoingPacketTooLarge;
        }
    }

    fn writeTransportPacket(
        self: *Connection,
        bytes: []u8,
    ) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        self.transport.writePacket(bytes) catch |err| {
            self.transport_unusable.store(true, .release);
            return err;
        };
    }

    fn writeTransportPacketParts(
        self: *Connection,
        prefix: []const u8,
        payload: []const u8,
    ) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        self.transport.writePacketParts(prefix, payload) catch |err| {
            self.transport_unusable.store(true, .release);
            return err;
        };
    }

    fn readPacket(self: *Connection) Error!OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        return self.readTransportPacket();
    }

    fn readPacketInto(
        self: *Connection,
        storage: []u8,
    ) Error!OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        const packet = try self.transport.readPacketInto(
            self.allocator,
            self.limits.max_packet_size,
            storage,
        );
        self.recordPacketReceived(packet.bytes.len);
        return self.finishReadPacket(packet);
    }

    fn readTransportPacket(self: *Connection) Error!OwnedPacket {
        const packet = try self.readUnvalidatedTransportPacket();
        return self.finishReadPacket(packet);
    }

    fn readUnvalidatedTransportPacket(
        self: *Connection,
    ) Error!packet_transport.OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        const packet = try self.transport.readPacket(
            self.allocator,
            self.limits.max_packet_size,
        );
        self.recordPacketReceived(packet.bytes.len);
        return packet;
    }

    fn readPacketWithInactivityTimeout(
        self: *Connection,
        timeout: std.Io.Clock.Duration,
    ) Error!OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        const packet = try self.transport.readPacketWithInactivityTimeout(
            self.allocator,
            self.limits.max_packet_size,
            timeout,
        );
        self.recordPacketReceived(packet.bytes.len);
        return self.finishReadPacket(packet);
    }

    fn readPacketWithInactivityTimeoutInto(
        self: *Connection,
        timeout: std.Io.Clock.Duration,
        storage: []u8,
    ) Error!OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        const packet = try self.transport
            .readPacketWithInactivityTimeoutInto(
            self.allocator,
            self.limits.max_packet_size,
            timeout,
            storage,
        );
        self.recordPacketReceived(packet.bytes.len);
        return self.finishReadPacket(packet);
    }

    fn readPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        return self.readTransportPacketWithDeadline(deadline);
    }

    fn readTransportPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedPacket {
        const packet = try self.readUnvalidatedTransportPacketWithDeadline(
            deadline,
        );
        return self.finishReadPacket(packet);
    }

    fn readUnvalidatedTransportPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!packet_transport.OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        const packet = try self.transport.readPacketWithDeadline(
            self.allocator,
            self.limits.max_packet_size,
            deadline,
        );
        self.recordPacketReceived(packet.bytes.len);
        return packet;
    }

    fn recordPacketReceived(self: *Connection, bytes: usize) void {
        self.traffic.recordReceivedExclusive(bytes);
        if (!self.traffic_sink_deferred) {
            if (self.traffic_sink) |counters| counters.recordReceived(bytes);
        }
    }

    fn recordPacketSent(self: *Connection, bytes: usize) void {
        self.traffic.recordSentExclusive(bytes);
        if (!self.traffic_sink_deferred) {
            if (self.traffic_sink) |counters| counters.recordSent(bytes);
        }
    }

    fn pendingPacketCount(self: *const Connection) usize {
        const pending = self.pending_packets orelse return 0;
        return pending.count();
    }

    fn ensurePendingPacketQueueAvailable(self: *Connection) Error!void {
        if (self.limits.max_pending_ping_packets == 0 or
            self.limits.max_pending_packet_bytes == 0)
        {
            return error.TooManyPendingPackets;
        }
        if (self.pending_packets) |pending| {
            return pending.ensureAvailable(self.limits.max_pending_ping_packets, self.limits.max_pending_packet_bytes);
        }
        const pending = try self.allocator.create(PendingPacketState);
        pending.* = .{};
        self.pending_packets = pending;
    }

    const AckReader = @import("runtime/acknowledgement/wait.zig").Reader(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const ErrorType = Error;
        pub const readPacket = Connection.readTransportPacket;
        pub const readPacketWithDeadline = Connection.readTransportPacketWithDeadline;
        pub const queuePacket = Connection.queuePendingPacket;

        pub fn retainOverflow(connection: *Connection, packet: OwnedPacket) void {
            connection.pending_packets.?.retainOverflow(packet);
        }
    });

    fn clearPendingPacketState(self: *Connection) void {
        const pending = self.pending_packets orelse return;
        pending.deinit(self.allocator);
        self.allocator.destroy(pending);
        self.pending_packets = null;
    }

    fn queuePendingPacket(
        self: *Connection,
        packet: OwnedPacket,
    ) Error!void {
        return self.pending_packets.?.append(self.allocator, packet, self.limits.max_pending_ping_packets, self.limits.max_pending_packet_bytes);
    }

    fn popPendingPacket(self: *Connection) ?OwnedPacket {
        const pending = self.pending_packets orelse return null;
        return pending.pop();
    }

    fn validateReadPacket(
        self: *Connection,
        packet: *const OwnedPacket,
    ) Error!void {
        // Validate wire syntax before semantic direction/state so a packet
        // that is wrong in both ways is still classified as Malformed Packet.
        try mqtt.validatePacketFlags(self.protocol, packet.fixed);
        try self.validateIncomingPacketType(packet.fixed.packet_type);
        self.authentication.ensurePacketAllowed(
            packet.fixed.packet_type,
        ) catch |err| {
            if (err == error.AuthenticationInProgress) {
                self.sendAuthenticationProtocolError();
            }
            return err;
        };
    }

    fn finishReadPacket(
        self: *Connection,
        packet_value: OwnedPacket,
    ) Error!OwnedPacket {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        try self.validateReadPacket(&packet);
        return packet;
    }

    fn validateOutgoingPacketType(
        self: *const Connection,
        packet_type: mqtt.PacketType,
    ) Error!void {
        switch (self.endpoint_role) {
            .unestablished => {},
            .client => try mqtt.validatePacketTypeForSender(
                packet_type,
                .client,
            ),
            .server => try mqtt.validatePacketTypeForSender(
                packet_type,
                .server,
            ),
        }
    }

    fn validateIncomingPacketType(
        self: *const Connection,
        packet_type: mqtt.PacketType,
    ) Error!void {
        switch (self.endpoint_role) {
            .unestablished => {},
            .client => try mqtt.validatePacketTypeForSender(
                packet_type,
                .server,
            ),
            .server => try mqtt.validatePacketTypeForSender(
                packet_type,
                .client,
            ),
        }
    }

    fn sendAuthenticationProtocolError(self: *Connection) void {
        if (self.protocol == .v5) {
            self.writeDisconnectWithProperties(0x82, &.{}) catch {};
        }
    }

    fn readAck(self: *Connection, packet_type: mqtt.PacketType) Error!OwnedAck {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != packet_type) return error.UnexpectedPacket;
        var ack = try mqtt.AckPacket.parsePayload(
            self.allocator,
            self.protocol,
            packet.fixed.packet_type,
            packet.fixed.flags,
            packet.remainingBytes(),
        );
        errdefer ack.deinit(self.allocator);
        try self.validateIncomingProperties(ack.properties);
        return .{ .packet = packet, .ack = ack };
    }

    fn nextPacketId(self: *Connection) u16 {
        const id = self.next_packet_id;
        self.next_packet_id +%= 1;
        if (self.next_packet_id == 0) self.next_packet_id = 1;
        return id;
    }

    fn reserveOutgoingPublish(self: *Connection, qos: mqtt.QoS) Error!u16 {
        if (self.outgoing_inflight >= self.max_outgoing_inflight) return error.InflightFull;

        const initial_packet_id = self.next_packet_id;
        errdefer self.next_packet_id = initial_packet_id;
        var attempts: usize = 0;
        while (attempts < std.math.maxInt(u16)) : (attempts += 1) {
            const packet_id = self.next_packet_id;
            if (self.packet_identifiers.containsOutgoing(packet_id)) {
                _ = self.nextPacketId();
                continue;
            }

            const stage: packet_identifiers.State.Stage = switch (qos) {
                .at_most_once => unreachable,
                .at_least_once => .outgoing_qos1,
                .exactly_once => .outgoing_qos2,
            };
            _ = try self.packet_identifiers.add(
                self.allocator,
                packet_id,
                stage,
            );
            _ = self.nextPacketId();
            self.outgoing_inflight += 1;
            return packet_id;
        }
        return error.InflightFull;
    }

    fn releaseOutgoingPublish(self: *Connection, packet_id: u16, qos: mqtt.QoS) void {
        const stage: packet_identifiers.State.Stage = switch (qos) {
            .at_most_once => return,
            .at_least_once => .outgoing_qos1,
            .exactly_once => .outgoing_qos2,
        };
        if (qos == .exactly_once and self.packet_identifiers.remove(
            packet_id,
            .outgoing_qos2_pubrel,
        )) {} else if (!self.packet_identifiers.remove(packet_id, stage)) return;
        self.outgoing_inflight -= 1;
    }
};

fn keepAliveTimeout(
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

test "MQTT Keep Alive timeout preserves half-second precision" {
    try std.testing.expect(keepAliveTimeout(0) == null);
    try std.testing.expectEqual(
        @as(i96, 1500 * std.time.ns_per_ms),
        keepAliveTimeout(1).?.raw.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 3 * std.time.ns_per_s),
        keepAliveTimeout(2).?.raw.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 98_302_500 * std.time.ns_per_ms),
        keepAliveTimeout(std.math.maxInt(u16)).?.raw.nanoseconds,
    );
}

fn validateUnsubAckResponse(protocol: mqtt.ProtocolVersion, unsuback: mqtt.UnsubAck, packet_id: u16, topic_filter_count: usize) Error!void {
    if (unsuback.packet_id != packet_id) return error.UnexpectedPacket;
    switch (protocol) {
        .v5 => if (unsuback.reason_codes.len != topic_filter_count) return error.UnexpectedPacket,
        // Pre-v5 UNSUBACK acknowledges only the Packet Identifier. Unlike
        // MQTT 5, it has no per-topic reason-code vector, so a single v3
        // UNSUBACK can validly confirm an UNSUBSCRIBE that contained multiple
        // topic filters.  Keep this aligned with rumqtt's v4 UnsubAck model.
        .v3_1, .v3_1_1 => {},
    }
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

test "owned CONNECT can replace username with a policy identity" {
    const allocator = std.testing.allocator;
    var owned = OwnedConnect{
        .packet = .{
            .bytes = try allocator.alloc(u8, 0),
            .fixed = undefined,
        },
        .connect = .{
            .protocol = .v5,
            .clean_start = true,
            .keep_alive_seconds = 60,
            .client_id = "client",
            .properties = try allocator.alloc(mqtt.Property, 0),
            .username = "wire-user",
            .password = "wire-password",
        },
    };
    defer owned.deinit(allocator);
    try owned.replaceUsername(allocator, "certificate-user");
    try std.testing.expectEqualStrings(
        "certificate-user",
        owned.connect.username.?,
    );
    try std.testing.expect(owned.connect.password == null);
    try owned.replaceUsername(allocator, "replacement-user");
    try std.testing.expectEqualStrings(
        "replacement-user",
        owned.connect.username.?,
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        owned.replaceUsername(allocator, "bad\x00user"),
    );
    try std.testing.expectEqualStrings(
        "replacement-user",
        owned.connect.username.?,
    );
}

test "MQTT runtime strict UTF-8 policy covers broker input fields" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    const accepted_control = "value\xc2\x9f";
    const connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = accepted_control,
        .username = accepted_control,
        .will = .{ .topic = accepted_control, .payload = "payload" },
    };
    const subscriptions = [_]mqtt.Subscription{.{
        .topic_filter = accepted_control,
    }};
    const filters = [_][]const u8{accepted_control};
    const properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = accepted_control,
        } },
    };
    const valid_properties = [_]mqtt.Property{
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "accepted",
        } },
        .{ .binary = .{
            .id = .correlation_data,
            .value = "opaque\x00\xff",
        } },
    };

    try connection.validateIncomingConnectUtf8(connect);
    try connection.validateIncomingUtf8(accepted_control);
    try connection.validateIncomingProperties(&properties);
    try connection.validateIncomingSubscriptionsUtf8(&subscriptions);
    try connection.validateIncomingTopicFiltersUtf8(&filters);

    connection.strict_utf8 = true;
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingConnectUtf8(connect),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingUtf8(accepted_control),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingProperties(&properties),
    );
    try connection.validateIncomingProperties(&valid_properties);
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingSubscriptionsUtf8(&subscriptions),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingTopicFiltersUtf8(&filters),
    );
}

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

    pub fn deinit(self: *OwnedPublish, allocator: std.mem.Allocator) void {
        self.publish.deinit(allocator);
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

test "MQTT runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
                .max_outgoing_topic_aliases = 2,
                .topic_alias_maximum = 4,
                .maximum_keep_alive_seconds = 7,
                .maximum_qos = .exactly_once,
                .retain_available = false,
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("client-1", accepted.connect.connect.client_id);
            try std.testing.expectEqualStrings("status/client-1", accepted.connect.connect.will.?.topic);
            try std.testing.expectEqualStrings("offline", accepted.connect.connect.will.?.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, accepted.connect.connect.will.?.qos);
            try std.testing.expectEqualStrings("rumq", accepted.connect.connect.username.?);
            try std.testing.expectEqualStrings("mq", accepted.connect.connect.password.?);
            try std.testing.expectEqual(@as(?u16, 5), mqtt.receiveMaximum(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(?u32, 4096), mqtt.maximumPacketSize(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(?u16, 4), mqtt.topicAliasMaximum(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(u16, 2), accepted.connection.max_outgoing_inflight);
            try std.testing.expectEqual(
                @as(u16, 2),
                accepted.connection.peer_topic_alias_maximum,
            );
            try std.testing.expectEqual(@as(usize, 4096), accepted.connection.peer_max_packet_size);
            try std.testing.expectEqual(@as(u16, 7), accepted.connection.keep_alive_seconds);

            var client_auth = try accepted.connection.readAuth();
            defer client_auth.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0x19), client_auth.auth.reason_code);
            try std.testing.expectEqualStrings("SCRAM-SHA-256", client_auth.auth.properties[0].utf8.value);
            try std.testing.expectEqualStrings("client-first", client_auth.auth.properties[1].binary.value);
            try accepted.connection.writeAuth(0x18, &.{
                .{ .utf8 = .{ .id = .reason_string, .value = "continue auth" } },
            });

            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(usize, 2), subscribe.subscribe.subscriptions.len);
            try std.testing.expectEqualStrings("sensors/+", subscribe.subscribe.subscriptions[0].topic_filter);
            try std.testing.expectEqualStrings("alerts/#", subscribe.subscribe.subscriptions[1].topic_filter);
            const reason_codes = [_]u8{ 0x01, 0x00 };
            try accepted.connection.writeSubAck(subscribe.subscribe.packet_id, &reason_codes, &.{});

            var unsubscribe = try accepted.connection.readUnsubscribe();
            defer unsubscribe.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(usize, 2), unsubscribe.unsubscribe.topic_filters.len);
            try std.testing.expectEqualStrings("sensors/+", unsubscribe.unsubscribe.topic_filters[0]);
            try std.testing.expectEqualStrings("alerts/#", unsubscribe.unsubscribe.topic_filters[1]);
            const unsub_reasons = [_]u8{ 0x00, 0x11 };
            // A broker may deliver ordinary traffic before the correlated
            // UNSUBACK. The client must preserve that packet for its next
            // reader instead of rejecting the valid interleaving.
            try accepted.connection.publish("alerts/system", "online", .{});
            try accepted.connection.writeUnsubAck(unsubscribe.unsubscribe.packet_id, &unsub_reasons, &.{});

            var exact = try accepted.connection.readPublish();
            defer exact.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("sensors/exact", exact.publish.topic);
            try std.testing.expectEqualStrings("exactly-once", exact.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, exact.publish.qos);
            try accepted.connection.writePubRec(exact.publish.packet_id.?, 0);
            var pubrel = try accepted.connection.readPubRel();
            defer pubrel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(exact.publish.packet_id.?, pubrel.ack.packet_id);
            try accepted.connection.writePubComp(pubrel.ack.packet_id, 0);

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("sensors/temp", publish.publish.topic);
            try std.testing.expectEqualStrings("21.5", publish.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, publish.publish.qos);
            try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);

            var alias_registered = try accepted.connection.readPublish();
            defer alias_registered.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("aliased/topic", alias_registered.publish.topic);
            try std.testing.expectEqualStrings("first", alias_registered.publish.payload);
            try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(alias_registered.publish.properties));

            var alias_reused = try accepted.connection.readPublish();
            defer alias_reused.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("aliased/topic", alias_reused.publish.topic);
            try std.testing.expectEqualStrings("second", alias_reused.publish.payload);
            try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(alias_reused.publish.properties));

            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var will_props = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 1 } }};
    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "client-1",
        .will = .{
            .topic = "status/client-1",
            .payload = "offline",
            .qos = .at_least_once,
            .properties = &will_props,
        },
        .username = "rumq",
        .password = "mq",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_packet_size = 2048,
        .max_outgoing_inflight = 3,
        .receive_maximum = 5,
        .topic_alias_maximum = 4,
        .max_outgoing_topic_aliases = 3,
        .outgoing_retain = false,
    });
    defer client.close();
    try std.testing.expectEqual(@as(u16, 2), client.max_outgoing_inflight);
    try std.testing.expectEqual(@as(u16, 5), client.max_incoming_inflight);
    try std.testing.expectEqual(@as(usize, 2048), client.peer_max_packet_size);
    try std.testing.expectEqual(@as(u16, 3), client.peer_topic_alias_maximum);
    try std.testing.expectEqual(@as(u16, 7), client.keep_alive_seconds);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, client.peerMaximumQoS());
    try std.testing.expect(!client.peerRetainAvailable());
    try std.testing.expect(!client.capabilities.outgoing_retain_enabled);

    try client.writeAuth(0x19, &.{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "client-first" } },
    });
    var auth = try client.readAuth();
    defer auth.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x18), auth.auth.reason_code);
    try std.testing.expectEqualStrings("continue auth", auth.auth.properties[0].utf8.value);

    const subscriptions = [_]mqtt.Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .at_most_once },
    };
    var suback = try client.subscribe(&subscriptions, .{});
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, suback.suback.reason_codes);

    const unsubscribe_filters = [_][]const u8{ "sensors/+", "alerts/#" };
    var unsuback = try client.unsubscribe(&unsubscribe_filters, .{});
    defer unsuback.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x11 }, unsuback.unsuback.reason_codes);

    var server_publish = try client.readPublish();
    defer server_publish.deinit(allocator);
    try std.testing.expectEqualStrings("alerts/system", server_publish.publish.topic);
    try std.testing.expectEqualStrings("online", server_publish.publish.payload);

    try client.publish("sensors/exact", "exactly-once", .{ .qos = .exactly_once });
    try client.publish("sensors/temp", "21.5", .{ .qos = .at_least_once });
    try client.publish("aliased/topic", "first", .{ .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }} });
    try client.publish("", "second", .{ .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }} });
    try client.ping();
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT exclusive traffic updates preserve wrapping counter semantics" {
    var counters: TrafficCounters = .{};
    counters.messages_received.store(std.math.maxInt(u64), .monotonic);
    counters.bytes_received.store(std.math.maxInt(u64) - 1, .monotonic);
    counters.messages_sent.store(std.math.maxInt(u64), .monotonic);
    counters.bytes_sent.store(std.math.maxInt(u64) - 2, .monotonic);

    counters.recordReceivedExclusive(2);
    counters.recordSentExclusive(3);
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 0,
            .messages_sent = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        },
        counters.stats(),
    );
}

test "MQTT deferred traffic sink flushes one exact connection delta" {
    var aggregate: TrafficCounters = .{};
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    connection.recordPacketReceived(7);
    connection.attachDeferredTrafficCounters(&aggregate);
    connection.attachDeferredTrafficCounters(&aggregate);
    connection.recordPacketReceived(11);
    connection.recordPacketSent(13);

    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 2,
            .messages_sent = 1,
            .bytes_received = 18,
            .bytes_sent = 13,
        },
        connection.trafficStats(),
    );
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 0,
            .messages_sent = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        },
        aggregate.stats(),
    );

    connection.flushDeferredTrafficCounters();
    connection.flushDeferredTrafficCounters();
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 0,
            .messages_sent = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        },
        connection.trafficStats(),
    );
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 2,
            .messages_sent = 1,
            .bytes_received = 18,
            .bytes_sent = 13,
        },
        aggregate.stats(),
    );
}

test "MQTT runtime counts complete control packets and wire bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var counters: TrafficCounters = .{};
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, server_stream),
        .traffic_sink = &counters,
        .protocol = .v5,
    };

    var ping_req: [mqtt.ping_packet_len]u8 = undefined;
    const request = mqtt.writePingInto(&ping_req, false);
    try stream_io.writeAllSlices(io, client_stream, &.{request});
    try connection.readPingReq();
    try connection.writePingResp();

    var ping_resp: [mqtt.ping_packet_len]u8 = undefined;
    var buffers = [_][]u8{&ping_resp};
    const received = try io.vtable.netRead(
        io.userdata,
        client_stream.socket.handle,
        &buffers,
    );
    try std.testing.expectEqual(ping_resp.len, received);
    try mqtt.validatePing(&ping_resp, true);

    const local = connection.trafficStats();
    const aggregate = counters.stats();
    try std.testing.expectEqual(@as(u64, 1), local.messages_received);
    try std.testing.expectEqual(@as(u64, 1), local.messages_sent);
    try std.testing.expectEqual(@as(u64, request.len), local.bytes_received);
    try std.testing.expectEqual(@as(u64, ping_resp.len), local.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1), aggregate.messages_received);
    try std.testing.expectEqual(@as(u64, 1), aggregate.messages_sent);
    try std.testing.expectEqual(
        @as(u64, request.len),
        aggregate.bytes_received,
    );
    try std.testing.expectEqual(@as(u64, ping_resp.len), aggregate.bytes_sent);
    try std.testing.expectEqualDeep(local, aggregate);
}

test "MQTT TCP server consumes PROXY v1 before CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_packet_size = 4096,
            .proxy_protocol = .v1,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            if (metadata.version != .v1 or metadata.command != .proxy) {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            const source = accepted.connection.remoteAddress();
            if (source != .ip4 or
                !std.mem.eql(u8, &source.ip4.bytes, &.{ 192, 0, 2, 5 }) or
                source.ip4.port != 6275)
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            if (!std.mem.eql(
                u8,
                accepted.connect.connect.client_id,
                "proxy-v1-client",
            )) {
                shared.err = error.InvalidClientId;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    try stream_io.writeAllParts(
        io,
        stream,
        "PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n",
        "",
    );
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
        .protocol = .v5,
        .limits = .{ .max_packet_size = 4096 },
    };
    stream_owned = false;
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-v1-client",
        .limits = .{ .max_packet_size = 4096 },
    });
    try std.testing.expect(attempt.accepted());
    var result = try attempt.requireAccepted();
    defer result.deinit(allocator);
    try result.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TCP PROXY v2 requires verified TLS metadata when configured" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.InvalidProperty,
        Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .proxy_v2_require_tls = true,
        }),
    );

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_packet_size = 4096,
            .proxy_protocol = .v2,
            .proxy_v2_require_tls = true,
            .proxy_v2_require_client_certificate = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            const tls = metadata.tls orelse {
                shared.err = error.MissingProxyTls;
                return;
            };
            if (!tls.client_ssl or !tls.verified or
                !tls.client_certificate_session or
                !std.mem.eql(u8, tls.common_name.?, "device-42"))
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            const common_name = accepted.connection
                .authenticatedProxyCommonName() orelse {
                shared.err = error.MissingAuthenticatedProxyIdentity;
                return;
            };
            if (!std.mem.eql(u8, common_name, "device-42")) {
                shared.err = error.InvalidProxyIdentity;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const address = [_]u8{
        192, 0, 2, 5, 127, 0, 0, 1, 0x18, 0x83, 0x07, 0x5b,
    };
    const ssl = [_]u8{
        0x05, 0,   0,   0,   0,   0x22, 0,   9, 'd', 'e',
        'v',  'i', 'c', 'e', '-', '4',  '2',
    };
    var proxy_header = proxy_protocol.v2_signature ++
        [_]u8{ 0x21, 0x11, 0, address.len + 3 + ssl.len } ++
        address ++ [_]u8{ 0x20, 0, ssl.len } ++ ssl;
    var empty = [_][]const u8{""};
    const remaining = try io.vtable.netWrite(
        io.userdata,
        stream.socket.handle,
        &proxy_header,
        &empty,
        0,
    );
    try std.testing.expectEqual(proxy_header.len, remaining);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
        .protocol = .v5,
        .limits = .{ .max_packet_size = 4096 },
    };
    stream_owned = false;
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-v2-tls",
        .limits = .{ .max_packet_size = 4096 },
    });
    try std.testing.expect(attempt.accepted());
    var accepted = try attempt.requireAccepted();
    defer accepted.deinit(allocator);
    try accepted.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT runtime resolves connection acceptance policies" {
    var pending = PendingAcceptedClient{
        .connection = undefined,
        .connect = .{
            .packet = undefined,
            .connect = .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 0,
                .client_id = "client",
            },
        },
    };
    const clean_options = try pending.resolvedOptions(.{
        .session_present = true,
    });
    try std.testing.expect(!clean_options.session_present);
    const v5_options = try pending.resolvedOptions(.{
        .server_keep_alive_seconds = 20,
        .maximum_keep_alive_seconds = 10,
    });
    try std.testing.expectEqual(@as(u8, 0), v5_options.reason_code);
    try std.testing.expectEqual(
        @as(?u16, 10),
        v5_options.server_keep_alive_seconds,
    );

    pending.connect.connect.protocol = .v3_1_1;
    pending.connect.connect.keep_alive_seconds = 11;
    const v311_options = try pending.resolvedOptions(.{
        .session_present = true,
        .assigned_client_identifier = "must-not-leak",
        .server_keep_alive_seconds = 9,
        .maximum_keep_alive_seconds = 10,
    });
    try std.testing.expectEqual(@as(u8, 0x02), v311_options.reason_code);
    try std.testing.expect(!v311_options.session_present);
    try std.testing.expect(v311_options.assigned_client_identifier == null);
    try std.testing.expect(v311_options.server_keep_alive_seconds == null);

    pending.connect.connect.protocol = .v5;
    pending.connect.connect.keep_alive_seconds = 10;
    const boundary = try pending.resolvedOptions(.{
        .maximum_keep_alive_seconds = 10,
    });
    try std.testing.expectEqual(
        @as(?u16, null),
        boundary.server_keep_alive_seconds,
    );

    pending.connect.connect.client_id = "";
    const anonymous = try pending.resolvedOptions(.{
        .allow_zero_length_client_id = false,
    });
    try std.testing.expectEqual(@as(u8, 0x80), anonymous.reason_code);
    pending.connect.connect.client_id = "will-client";
    pending.connect.connect.will = .{
        .topic = "will/topic",
        .payload = "will",
        .qos = .at_least_once,
        .retain = false,
    };
    const v5_will = try pending.resolvedOptions(.{
        .maximum_qos = .at_most_once,
    });
    try std.testing.expectEqual(@as(u8, 0x9b), v5_will.reason_code);
    pending.connect.connect.protocol = .v3_1_1;
    const v311_will = try pending.resolvedOptions(.{
        .maximum_qos = .at_most_once,
    });
    try std.testing.expectEqual(@as(u8, 0x05), v311_will.reason_code);
    try std.testing.expectError(
        error.InvalidProperty,
        pending.resolvedOptions(.{ .maximum_keep_alive_seconds = 0 }),
    );
}

test "MQTT Connection allocates PROXY metadata on demand" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };
    const metadata = proxy_protocol.Metadata{
        .allocator = std.testing.allocator,
        .version = .v2,
        .command = .local,
        .source_unix = try std.testing.allocator.dupe(u8, "source.sock"),
    };

    try std.testing.expect(connection.proxyMetadata() == null);
    try std.testing.expectError(
        error.OutOfMemory,
        connection.attachProxyMetadata(metadata),
    );
    try std.testing.expect(connection.proxyMetadata() == null);
    try std.testing.expectEqual(proxy_protocol.Version.v2, metadata.version);
    try std.testing.expectEqualStrings("source.sock", metadata.source_unix.?);

    connection.allocator = std.testing.allocator;
    try connection.attachProxyMetadata(metadata);
    try std.testing.expectEqual(
        proxy_protocol.Version.v2,
        connection.proxyMetadata().?.version,
    );
    connection.clearProxyMetadata();
    try std.testing.expect(connection.proxyMetadata() == null);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 800), @sizeOf(Connection));
        try std.testing.expectEqual(
            @as(usize, 2),
            @sizeOf(ConnectionCapabilities),
        );
        try std.testing.expectEqual(
            @sizeOf(?*proxy_protocol.Metadata),
            @sizeOf(@FieldType(Connection, "proxy_metadata")),
        );
    }
}

test "MQTT Connection uses stack-first write property staging" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
    };
    defer connection.clearWritePropertyOverflow();

    var stack: [write_property_staging_capacity]mqtt.Property = undefined;
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    connection.allocator = no_alloc.allocator();
    const common = try connection.writePropertyList(&stack, stack.len);
    try std.testing.expectEqual(stack[0..].ptr, common.items.ptr);
    try std.testing.expect(connection.write_property_overflow == null);
    try std.testing.expect(!no_alloc.has_induced_failure);

    try std.testing.expectError(
        error.OutOfMemory,
        connection.writePropertyList(&stack, stack.len + 1),
    );
    try std.testing.expect(connection.write_property_overflow == null);

    connection.allocator = allocator;
    const overflow = try connection.writePropertyList(
        &stack,
        stack.len + 1,
    );
    try std.testing.expect(overflow.items.ptr != stack[0..].ptr);
    try std.testing.expectEqual(stack.len + 1, overflow.capacity);

    var warmed = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    connection.allocator = warmed.allocator();
    const reused = try connection.writePropertyList(
        &stack,
        stack.len + 1,
    );
    try std.testing.expectEqual(overflow.items.ptr, reused.items.ptr);
    try std.testing.expect(!warmed.has_induced_failure);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @as(usize, 16),
            @sizeOf(@FieldType(Connection, "write_property_overflow")),
        );
    }
}

test "MQTT Connection owns listener namespace compactly" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };

    try std.testing.expectEqualStrings("", connection.topicNamespace());
    try std.testing.expectError(
        error.OutOfMemory,
        connection.setTopicNamespace("tenant/"),
    );
    try std.testing.expectEqualStrings("", connection.topicNamespace());

    connection.allocator = std.testing.allocator;
    try connection.setTopicNamespace("tenant/");
    try std.testing.expectEqualStrings("tenant/", connection.topicNamespace());
    try std.testing.expectEqualStrings(
        "sensor",
        try connection.visibleTopic("tenant/sensor"),
    );
    try std.testing.expectError(
        error.TopicOutsideNamespace,
        connection.visibleTopic("other/sensor"),
    );

    var replacement_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = replacement_failure.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.setTopicNamespace("replacement/"),
    );
    try std.testing.expectEqualStrings("tenant/", connection.topicNamespace());
    connection.allocator = std.testing.allocator;

    const maximum_prefix = try std.testing.allocator.alloc(
        u8,
        std.math.maxInt(u16),
    );
    defer std.testing.allocator.free(maximum_prefix);
    @memset(maximum_prefix, 'a');
    try connection.setTopicNamespace(maximum_prefix);
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(u16)),
        connection.topicNamespace().len,
    );

    const oversized_prefix = try std.testing.allocator.alloc(
        u8,
        @as(usize, std.math.maxInt(u16)) + 1,
    );
    defer std.testing.allocator.free(oversized_prefix);
    @memset(oversized_prefix, 'b');
    try std.testing.expectError(
        error.InvalidTopic,
        connection.setTopicNamespace(oversized_prefix),
    );
    try std.testing.expectEqualSlices(
        u8,
        maximum_prefix,
        connection.topicNamespace(),
    );

    try connection.setTopicNamespace("");
    try std.testing.expect(connection.topic_namespace_ptr == null);
    try std.testing.expectEqual(@as(u16, 0), connection.topic_namespace_len);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @sizeOf(?[*]u8),
            @sizeOf(@FieldType(Connection, "topic_namespace_ptr")),
        );
        try std.testing.expectEqual(
            @sizeOf(u16),
            @sizeOf(@FieldType(Connection, "topic_namespace_len")),
        );
    }
}

test "MQTT Connection stores the complete optional CONNECT level" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    try std.testing.expect(connection.incomingConnectLevel() == null);

    connection.setIncomingConnectLevel(0);
    try std.testing.expectEqual(
        @as(?u8, 0),
        connection.incomingConnectLevel(),
    );
    connection.setIncomingConnectLevel(std.math.maxInt(u8));
    try std.testing.expectEqual(
        @as(?u8, std.math.maxInt(u8)),
        connection.incomingConnectLevel(),
    );

    connection.setIncomingConnectLevel(null);
    try std.testing.expect(connection.incomingConnectLevel() == null);
}

test "MQTT Connection retains only post-admission limits" {
    const configured = Limits{
        .max_packet_size = 12_345,
        .max_pending_ping_packets = 7,
        .max_pending_packet_bytes = 2_048,
        .tcp_nodelay = false,
        .proxy_protocol = .v2,
        .proxy_v2_require_tls = true,
        .proxy_v2_require_client_certificate = true,
        .proxy_header_timeout = .fromSeconds(9),
    };
    const active = ConnectionLimits.from(configured);
    try std.testing.expectEqual(
        configured.max_packet_size,
        active.max_packet_size,
    );
    try std.testing.expectEqual(
        configured.max_pending_ping_packets,
        active.max_pending_ping_packets,
    );
    try std.testing.expectEqual(configured.max_pending_packet_bytes, active.max_pending_packet_bytes);
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 24), @sizeOf(ConnectionLimits));
    }

    const connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .limits = active,
        .proxy_v2_require_client_certificate = configured.proxy_v2_require_client_certificate,
    };
    try std.testing.expect(connection.proxy_v2_require_client_certificate);
}

test "MQTT Connection stores assigned Client ID with wire length" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };
    try std.testing.expect(connection.assignedClientId() == null);
    try std.testing.expectError(
        error.OutOfMemory,
        connection.setAssignedClientId("generated-client"),
    );
    try std.testing.expect(connection.assignedClientId() == null);

    connection.allocator = std.testing.allocator;
    try connection.setAssignedClientId("generated-client");
    try std.testing.expectEqualStrings(
        "generated-client",
        connection.assignedClientId().?,
    );
    connection.clearAssignedClientId();
    try std.testing.expect(connection.assignedClientId() == null);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @sizeOf(?[*]u8),
            @sizeOf(@FieldType(Connection, "assigned_client_id_ptr")),
        );
        try std.testing.expectEqual(
            @sizeOf(u16),
            @sizeOf(@FieldType(Connection, "assigned_client_id_len")),
        );
    }
}

test "MQTT Connection allocates Topic Alias tables by direction" {
    const property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};
    var descriptor_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = descriptor_failure.allocator(),
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer connection.clearTopicAliases();

    try std.testing.expect(connection.incoming_topic_aliases == null);
    try std.testing.expect(connection.outgoing_topic_aliases == null);
    try std.testing.expectError(
        error.OutOfMemory,
        connection.prepareOutgoingTopicAliasCommit("alias/topic", &property),
    );
    try std.testing.expect(connection.outgoing_topic_aliases == null);

    var table_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    connection.allocator = table_failure.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.prepareOutgoingTopicAliasCommit("alias/topic", &property),
    );
    try std.testing.expect(connection.outgoing_topic_aliases == null);

    connection.allocator = std.testing.allocator;
    try connection.prepareOutgoingTopicAliasCommit("alias/topic", &property);
    try std.testing.expectEqualStrings(
        "alias/topic",
        connection.outgoingTopicAlias(1).?,
    );
    try std.testing.expect(connection.incoming_topic_aliases == null);

    var incoming = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "incoming/topic",
        .packet_id = null,
        .properties = @constCast(&property),
        .payload = "payload",
    };
    try connection.applyIncomingTopicAlias(&incoming);
    try std.testing.expectEqualStrings(
        "incoming/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expect(connection.outgoing_topic_aliases != null);

    if (@sizeOf(usize) == 8) {
        const table_size: usize = switch (builtin.mode) {
            .Debug, .ReleaseSafe => 32,
            .ReleaseFast, .ReleaseSmall => 24,
        };
        try std.testing.expectEqual(table_size, @sizeOf(topic_alias.Table));
        try std.testing.expectEqual(
            @sizeOf(?*topic_alias.Table),
            @sizeOf(@FieldType(Connection, "incoming_topic_aliases")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*topic_alias.Table),
            @sizeOf(@FieldType(Connection, "outgoing_topic_aliases")),
        );
    }
}

test "MQTT Connection allocates response waiting state on demand" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };

    try std.testing.expect(connection.pending_packets == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingPacketCount());
    try std.testing.expectError(
        error.OutOfMemory,
        connection.ensurePendingPacketQueueAvailable(),
    );
    try std.testing.expect(connection.pending_packets == null);

    connection.allocator = std.testing.allocator;
    try connection.ensurePendingPacketQueueAvailable();
    try std.testing.expect(connection.pending_packets != null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingPacketCount());
    connection.clearPendingPacketState();
    try std.testing.expect(connection.pending_packets == null);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 96), @sizeOf(PendingPacketState));
        try std.testing.expectEqual(
            @sizeOf(?*PendingPacketState),
            @sizeOf(@FieldType(Connection, "pending_packets")),
        );
    }
}

test "MQTT client rejects Session Present after Clean Start" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
                var peer = PacketTransport.initTcp(
                    self.io,
                    try self.listener.accept(self.io),
                );
                defer peer.close(self.allocator);
                var packet = try peer.readPacket(self.allocator, 4096);
                defer packet.deinit(self.allocator);
                var connect = try mqtt.Connect.parse(
                    self.allocator,
                    packet.bytes,
                );
                defer connect.deinit(self.allocator);
                try std.testing.expectEqual(protocol, connect.protocol);
                try std.testing.expect(connect.clean_start);

                var invalid_connack = [_]u8{
                    0x20,
                    if (protocol == .v5) 0x03 else 0x02,
                    0x01,
                    0x00,
                    0x00,
                };
                const response_len: usize = if (protocol == .v5) 5 else 4;
                try peer.writePacket(invalid_connack[0..response_len]);
            }
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        try std.testing.expectError(
            error.InvalidFlags,
            Client.connectAttempt(allocator, io, listener.socket.address, .{
                .protocol = protocol,
                .client_id = "clean-client",
                .clean_start = true,
                .limits = .{ .max_packet_size = 4096 },
            }),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT runtime exposes CONNACK session present" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("resuming-client", accepted.connect.connect.client_id);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var result = try Client.connectWithConnAck(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "resuming-client",
        .clean_start = false,
        .limits = .{ .max_packet_size = 4096 },
    });
    defer result.deinit(allocator);
    try std.testing.expect(result.connack.connack.session_present);
    try result.connection.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT server rejects Will above its advertised Maximum QoS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            _ = shared.server.accept(.{
                .protocol = .v5,
                .maximum_qos = .at_most_once,
            }) catch |err| {
                if (err != error.InvalidQoS) shared.err = err;
                return;
            };
            shared.err = error.TestUnexpectedResult;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var attempt = try Client.connectAttempt(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "maximum-qos-will",
            .will = .{
                .topic = "will/maximum-qos",
                .payload = "blocked",
                .qos = .at_least_once,
            },
            .limits = .{ .max_packet_size = 4096 },
        },
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u8, 0x9b), attempt.connack.connack.reason_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT server rejects retained Will when retain is unavailable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            _ = shared.server.accept(.{
                .protocol = .v5,
                .retain_available = false,
            }) catch |err| {
                if (err != error.InvalidProperty) shared.err = err;
                return;
            };
            shared.err = error.TestUnexpectedResult;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var attempt = try Client.connectAttempt(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "retained-will",
            .will = .{
                .topic = "will/retain",
                .payload = "blocked",
                .retain = true,
            },
            .limits = .{ .max_packet_size = 4096 },
        },
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u8, 0x9a), attempt.connack.connack.reason_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client connectAttempt exposes refused CONNACK reason" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .reason_code = 0x87, // Not authorized.
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("refused-client", accepted.connect.connect.client_id);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var attempt = try Client.connectAttempt(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "refused-client",
        .limits = .{ .max_packet_size = 4096 },
    });
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expect(attempt.connection == null);
    try std.testing.expectEqual(@as(u8, 0x87), attempt.connack.connack.reason_code);
    try std.testing.expectEqual(@as(usize, 0), attempt.connack.connack.properties.len);

    thread.join();
    if (shared.err) |err| return err;

    var second_server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer second_server.deinit();
    var second_shared = Shared{ .server = &second_server };
    const second_thread = try std.Thread.spawn(.{}, Shared.run, .{&second_shared});
    try std.testing.expectError(error.ConnectRefused, Client.connectWithConnAck(allocator, io, second_server.address(), .{
        .protocol = .v5,
        .client_id = "refused-client",
        .limits = .{ .max_packet_size = 4096 },
    }));
    second_thread.join();
    if (second_shared.err) |err| return err;
}

test "MQTT server reports version-aware CONNECT failures" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            for (0..9) |_| {
                const stream = self.listener.accept(self.io) catch |err| {
                    self.err = err;
                    return;
                };
                var connection = Connection{
                    .allocator = self.allocator,
                    .transport = .initTcp(self.io, stream),
                };
                var pending = connection.acceptPending(.{
                    .connect_timeout = .fromMilliseconds(500),
                }) catch {
                    connection.close();
                    continue;
                };
                pending.deinit(self.allocator);
                self.err = error.TestUnexpectedResult;
                return;
            }
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "unsupported-level",
    });
    const level_index = (try mqtt.FixedHeader.parse(encoded.items)).header_len +
        2 + "MQTT".len;
    const valid_v5 = try allocator.dupe(u8, encoded.items);
    defer allocator.free(valid_v5);
    const mismatched_v31 = try allocator.dupe(u8, valid_v5);
    defer allocator.free(mismatched_v31);
    mismatched_v31[level_index] = 3;
    const unsupported_v6 = try allocator.dupe(u8, valid_v5);
    defer allocator.free(unsupported_v6);
    unsupported_v6[level_index] = 6;
    const invalid_flags = try allocator.dupe(u8, valid_v5);
    defer allocator.free(invalid_flags);
    invalid_flags[0] = 0x1f;
    const cases = [_]struct { packet: []const u8, expected: ?[]const u8 }{
        .{
            .packet = mismatched_v31,
            .expected = &.{ 0x20, 0x02, 0x00, 0x01 },
        },
        .{
            .packet = unsupported_v6,
            .expected = &.{ 0x20, 0x03, 0x00, 0x84, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x0c, 0x00, 0x04, 'M',  'Q',  'T', 'T',
                0x04, 0x00, 0x00, 0x0a, 0x00, 0x00,
            },
            .expected = &.{ 0x20, 0x02, 0x00, 0x02 },
        },
        .{
            .packet = &.{
                0x10, 0x26, 0x00, 0x06, 'M',  'Q',  'I', 's', 'd', 'p',
                0x03, 0x02, 0x00, 0x0a, 0x00, 0x18, 'a', 'b', 'c', 'd',
                'e',  'f',  'g',  'h',  'i',  'j',  'k', 'l', 'm', 'n',
                'o',  'p',  'q',  'r',  's',  't',  'u', 'v', 'w', 'x',
            },
            .expected = &.{ 0x20, 0x02, 0x00, 0x02 },
        },
        .{
            .packet = invalid_flags,
            .expected = &.{ 0x20, 0x03, 0x00, 0x81, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x07, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05,
            },
            .expected = &.{ 0x20, 0x03, 0x00, 0x81, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x15, 0x00, 0x04, 'M',  'Q',  'T',  'T',
                0x05, 0x06, 0x00, 0x0a, 0x00, 0x00, 0x01, 'p',
                0x00, 0x00, 0x01, '#',  0x00, 0x01, 'p',
            },
            .expected = &.{ 0x20, 0x03, 0x00, 0x90, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x0d, 0x00, 0x04, 'M',  'Q',  'T',  'U',
                0x05, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00,
            },
            .expected = null,
        },
        .{
            .packet = &.{ 0x10, 0x06, 0x00, 0x04, 'M', 'Q', 'T', 'T' },
            .expected = null,
        },
    };
    const Peer = struct {
        fn run(
            peer_io: std.Io,
            peer_allocator: std.mem.Allocator,
            address: net.IpAddress,
            packet: []const u8,
            expected: ?[]const u8,
        ) !void {
            const stream = try address.connect(
                peer_io,
                .{ .mode = .stream },
            );
            defer stream.close(peer_io);
            try stream_io.writeAllSlices(peer_io, stream, &.{packet});
            var peer = PacketTransport.initTcp(peer_io, stream);
            const deadline = peer.deadlineFromNow(.fromMilliseconds(500));
            const expected_bytes = expected orelse {
                var received = peer.readPacketWithDeadline(
                    peer_allocator,
                    mqtt.ConnAck.no_properties_max_len,
                    deadline,
                ) catch |err| switch (err) {
                    error.EndOfStream,
                    error.ConnectionClosed,
                    error.SocketUnconnected,
                    error.ConnectionResetByPeer,
                    => return,
                    else => return err,
                };
                defer received.deinit(peer_allocator);
                return error.TestUnexpectedResult;
            };
            var received = try peer.readPacketWithDeadline(
                peer_allocator,
                mqtt.ConnAck.no_properties_max_len,
                deadline,
            );
            defer received.deinit(peer_allocator);
            try std.testing.expectEqualSlices(
                u8,
                expected_bytes,
                received.bytes,
            );
        }
    };
    var peer_err: ?anyerror = null;
    for (cases) |case| {
        Peer.run(
            io,
            allocator,
            listener.socket.address,
            case.packet,
            case.expected,
        ) catch |err| if (peer_err == null) {
            peer_err = err;
        };
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    if (peer_err) |err| return err;
}

test "MQTT client follows bounded Server Reference CONNACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var redirector = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer redirector.deinit();
    var destination = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer destination.deinit();

    const Shared = struct {
        redirector: *Server,
        destination: *Server,
        reference: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.redirector.acceptPending(.{
                .protocol = .v5,
            });
            defer first.deinit(self.redirector.allocator);
            try first.connection.writeConnAck(.{
                .reason_code = 0x9c,
                .properties = &.{.{ .utf8 = .{
                    .id = .server_reference,
                    .value = self.reference,
                } }},
            });
            var second = try self.destination.accept(.{ .protocol = .v5 });
            defer second.deinit(self.destination.allocator);
            try std.testing.expectEqualStrings(
                "redirect-client",
                second.connect.connect.client_id,
            );
            var disconnect = try second.connection.readDisconnect();
            defer disconnect.deinit(self.destination.allocator);
        }
    };
    const reference = try std.fmt.allocPrint(
        allocator,
        "redirect-b.mqtt.resolver.test:{d}",
        .{destination.address().ip4.port},
    );
    defer allocator.free(reference);
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .reference = reference,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "mqtt://redirect-a.mqtt.resolver.test:{d}",
        .{redirector.address().ip4.port},
    );
    defer allocator.free(initial_uri);
    const Resolver = struct {
        redirect_address: net.IpAddress,
        destination_address: net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            const address = if (std.mem.eql(
                u8,
                host,
                "redirect-a.mqtt.resolver.test",
            ))
                self.redirect_address
            else if (std.mem.eql(
                u8,
                host,
                "redirect-b.mqtt.resolver.test",
            ))
                self.destination_address
            else
                return error.UnknownHostName;
            if (address.getPort() != port or deadline == null) {
                return error.Timeout;
            }
            const addresses = try resolve_allocator.alloc(net.IpAddress, 1);
            addresses[0] = address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .redirect_address = redirector.address(),
        .destination_address = destination.address(),
    };
    var result = try Client.connectUriFollowingRedirects(
        allocator,
        io,
        initial_uri,
        .{
            .protocol = .v5,
            .client_id = "redirect-client",
            .network_connect_timeout = .fromSeconds(3),
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
            .limits = .{ .max_packet_size = 4096 },
        },
        .{ .max_redirects = 1 },
    );
    defer result.deinit(allocator);
    try result.connection.disconnect(0);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 2), resolver.calls.load(.acquire));
}

test "MQTT connection enforces outgoing inflight limit before writing" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .outgoing_inflight = 1,
        .max_outgoing_inflight = 1,
    };

    try std.testing.expectError(error.InflightFull, connection.publish("limited/topic", "blocked", .{ .qos = .at_least_once }));
    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
}

test "MQTT acknowledgement apply preserves wrong-stage inflight state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .outgoing_inflight = 2,
    };
    defer connection.packet_identifiers.deinit(allocator);
    try std.testing.expect(try connection.packet_identifiers.add(
        allocator,
        41,
        .outgoing_qos1,
    ));
    try std.testing.expect(try connection.packet_identifiers.add(
        allocator,
        42,
        .outgoing_qos2,
    ));

    try std.testing.expectError(
        error.UnexpectedPacket,
        connection.applyPubAck(.{
            .packet_type = .puback,
            .packet_id = 42,
        }),
    );
    try std.testing.expectError(
        error.UnexpectedPacket,
        connection.applyPubRec(.{
            .packet_type = .pubrec,
            .packet_id = 41,
        }),
    );
    try std.testing.expectError(
        error.UnexpectedPacket,
        connection.applyPubComp(.{
            .packet_type = .pubcomp,
            .packet_id = 42,
        }),
    );
    try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
    try std.testing.expect(connection.packet_identifiers.contains(
        41,
        .outgoing_qos1,
    ));
    try std.testing.expect(connection.packet_identifiers.contains(
        42,
        .outgoing_qos2,
    ));
}

test "MQTT duplicate successful PUBREC retransmits PUBREL" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .outgoing_inflight = 1,
    };
    defer connection.packet_identifiers.deinit(allocator);
    try std.testing.expect(try connection.packet_identifiers.add(
        allocator,
        42,
        .outgoing_qos2_pubrel,
    ));

    try connection.applyPubRec(.{
        .packet_type = .pubrec,
        .packet_id = 42,
    });
    var peer = PacketTransport.initTcp(io, server_stream);
    var repeated = try peer.readPacket(allocator, 16);
    defer repeated.deinit(allocator);
    var pubrel = try mqtt.AckPacket.parse(allocator, .v5, repeated.bytes);
    defer pubrel.deinit(allocator);
    try std.testing.expectEqual(mqtt.PacketType.pubrel, pubrel.packet_type);
    try std.testing.expectEqual(@as(u16, 42), pubrel.packet_id);
    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
    try std.testing.expect(connection.packet_identifiers.contains(
        42,
        .outgoing_qos2_pubrel,
    ));
}

test "MQTT split publish API pipelines QoS publishes up to receive maximum" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);

            var first = try accepted.connection.readPublish();
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("pipeline/one", first.publish.topic);
            try std.testing.expectEqualStrings("one", first.publish.payload);

            var second = try accepted.connection.readPublish();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("pipeline/two", second.publish.topic);
            try std.testing.expectEqualStrings("two", second.publish.payload);

            // Delay acknowledgements until both publishes have arrived. This
            // proves the client API can actually fill the negotiated in-flight
            // window instead of waiting for each PUBACK before writing the next
            // PUBLISH, matching rumqtt's state-machine model.
            try accepted.connection.writePubAck(first.publish.packet_id.?, 0);
            try accepted.connection.writePubAck(second.publish.packet_id.?, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "pipeline-client",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_inflight = 2,
    });
    defer client.close();
    try std.testing.expectEqual(@as(u16, 2), client.max_outgoing_inflight);

    const first_id = (try client.writePublish("pipeline/one", "one", .{ .qos = .at_least_once })).?;
    const second_id = (try client.writePublish("pipeline/two", "two", .{ .qos = .at_least_once })).?;
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);
    try std.testing.expectError(error.InflightFull, client.writePublish("pipeline/three", "three", .{ .qos = .at_least_once }));

    try client.completePublishPubAck(first_id);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try client.completePublishPubAck(second_id);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT split publish API accepts out-of-order QoS1 PUBACKs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);

            var first = try accepted.connection.readPublish();
            defer first.deinit(server_ptr.allocator);
            var second = try accepted.connection.readPublish();
            defer second.deinit(server_ptr.allocator);

            // A real broker is not required to acknowledge QoS 1 publishes in
            // send order.  Rumqtt tracks in-flight publishes by Packet
            // Identifier; the split API should likewise let callers retire the
            // ACK that actually arrived instead of forcing head-of-line order.
            try accepted.connection.writePubAck(second.publish.packet_id.?, 0);
            try accepted.connection.writePubAck(first.publish.packet_id.?, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "out-of-order-puback",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_inflight = 2,
    });
    defer client.close();

    const first_id = (try client.writePublish("ack/one", "one", .{ .qos = .at_least_once })).?;
    const second_id = (try client.writePublish("ack/two", "two", .{ .qos = .at_least_once })).?;
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    // Passing 0 means "complete whichever PUBACK arrives next".  This keeps
    // the API simple for event-loop users that read acks from the wire before
    // dispatching them to request waiters.
    try client.completePublishPubAck(0);
    try std.testing.expect(!client.packet_identifiers.contains(
        second_id,
        .outgoing_qos1,
    ));
    try std.testing.expect(client.packet_identifiers.contains(
        first_id,
        .outgoing_qos1,
    ));
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try client.completePublishPubAck(0);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT split publish API accepts out-of-order QoS2 PUBREC handshakes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);

            var first = try accepted.connection.readPublish();
            defer first.deinit(server_ptr.allocator);
            var second = try accepted.connection.readPublish();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, first.publish.qos);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, second.publish.qos);

            try accepted.connection.writePubRec(second.publish.packet_id.?, 0);
            try accepted.connection.writePubRec(first.publish.packet_id.?, 0);

            var second_rel = try accepted.connection.readPubRel();
            defer second_rel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(second.publish.packet_id.?, second_rel.ack.packet_id);

            var first_rel = try accepted.connection.readPubRel();
            defer first_rel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(first.publish.packet_id.?, first_rel.ack.packet_id);

            try accepted.connection.writePubComp(second_rel.ack.packet_id, 0);
            try accepted.connection.writePubComp(first_rel.ack.packet_id, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "out-of-order-pubrec",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_inflight = 2,
    });
    defer client.close();

    const first_id = (try client.writePublish("qos2/one", "one", .{ .qos = .exactly_once })).?;
    const second_id = (try client.writePublish("qos2/two", "two", .{ .qos = .exactly_once })).?;
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    const second_rec = try client.completePublishPubRec(0);
    try std.testing.expectEqual(second_id, second_rec);
    try std.testing.expect(!client.packet_identifiers.contains(
        second_id,
        .outgoing_qos2,
    ));
    try std.testing.expect(client.packet_identifiers.contains(
        second_id,
        .outgoing_qos2_pubrel,
    ));
    try std.testing.expect(client.packet_identifiers.contains(
        first_id,
        .outgoing_qos2,
    ));
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    const first_rec = try client.completePublishPubRec(0);
    try std.testing.expectEqual(first_id, first_rec);
    try std.testing.expect(client.packet_identifiers.contains(
        first_id,
        .outgoing_qos2_pubrel,
    ));
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    try client.completePublishPubComp(second_id);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try client.completePublishPubComp(first_id);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT Receive Maximum cannot raise local outgoing inflight cap" {
    try std.testing.expectEqual(@as(u16, 2), negotiatedOutgoingInflightLimit(2, 3));
    try std.testing.expectEqual(@as(u16, 2), negotiatedOutgoingInflightLimit(3, 2));
    try std.testing.expectEqual(@as(u16, 1), negotiatedOutgoingInflightLimit(1, 1));
}

test "MQTT client Receive Maximum has an independent compatibility fallback" {
    try std.testing.expectEqual(
        @as(u16, 16),
        (ConnectOptions{ .client_id = "default" }).effectiveReceiveMaximum(),
    );
    try std.testing.expectEqual(
        @as(u16, 7),
        (ConnectOptions{
            .client_id = "configured",
            .max_outgoing_inflight = 3,
            .receive_maximum = 7,
        }).effectiveReceiveMaximum(),
    );
    const properties = [_]mqtt.Property{.{ .two_byte = .{
        .id = .receive_maximum,
        .value = 11,
    } }};
    try std.testing.expectEqual(
        @as(u16, 11),
        (ConnectOptions{
            .client_id = "property",
            .max_outgoing_inflight = 3,
            .receive_maximum = 7,
            .properties = &properties,
        }).effectiveReceiveMaximum(),
    );
}

test "MQTT v3 UNSUBACK validates packet id without per-filter reasons" {
    var v3_reasons = [_]u8{0x00};
    const v3_ack = mqtt.UnsubAck{
        .packet_id = 12,
        .properties = &.{},
        .reason_codes = &v3_reasons,
    };
    try validateUnsubAckResponse(.v3_1_1, v3_ack, 12, 2);
    try std.testing.expectError(error.UnexpectedPacket, validateUnsubAckResponse(.v3_1_1, v3_ack, 13, 2));

    var v5_reasons = [_]u8{ 0x00, 0x11 };
    const v5_ack = mqtt.UnsubAck{
        .packet_id = 12,
        .properties = &.{},
        .reason_codes = &v5_reasons,
    };
    try validateUnsubAckResponse(.v5, v5_ack, 12, 2);
    try std.testing.expectError(error.UnexpectedPacket, validateUnsubAckResponse(.v5, v5_ack, 12, 1));
}

test "MQTT connection enforces negotiated maximum packet size" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_max_packet_size = 8,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);
    defer connection.write_scratch.deinit(std.testing.allocator);

    try std.testing.expectError(error.OutgoingPacketTooLarge, connection.publish("limited/topic", "payload too large", .{}));
}

test "MQTT borrowed PUBLISH preserves preflight errors and inflight state" {
    const alias_property = [_]mqtt.Property{.{
        .two_byte = .{ .id = .topic_alias, .value = 1 },
    }};
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = .{ .tcp = undefined },
        .protocol = .v5,
        .peer_max_packet_size = 8,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);
    defer connection.write_scratch.deinit(std.testing.allocator);
    defer connection.clearOutgoingTopicAliases();

    try std.testing.expectError(
        error.OutgoingPacketTooLarge,
        connection.writePublish("too/large", "payload", .{
            .qos = .at_least_once,
            .properties = &alias_property,
        }),
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        connection.outgoingTopicAlias(1),
    );
    try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.packet_identifiers.count(.outgoing_qos1),
    );
    try std.testing.expect(connection.isUsable());

    try connection.prepareOutgoingTopicAliasCommit(
        "existing/topic",
        &alias_property,
    );
    connection.peer_max_packet_size = std.math.maxInt(usize);
    connection.authentication.phase = .reauthenticating;
    try std.testing.expectError(
        error.AuthenticationInProgress,
        connection.writePublish("auth/blocked", "payload", .{
            .qos = .at_least_once,
            .properties = &alias_property,
        }),
    );
    try std.testing.expectEqualStrings(
        "existing/topic",
        connection.outgoingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.packet_identifiers.count(.outgoing_qos1),
    );
    try std.testing.expect(connection.isUsable());
}

test "MQTT publish encoding reuses connection scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    defer connection.packet_identifiers.deinit(allocator);
    defer connection.write_scratch.deinit(allocator);

    const payload = [_]u8{0xa5} ** 1024;
    _ = try connection.writePublish("scratch/topic", &payload, .{});
    const storage = connection.write_scratch.allocatedSlice().ptr;
    const prefix_capacity = connection.write_scratch.capacity;
    try std.testing.expect(connection.write_scratch.items.len < payload.len);
    var peer = PacketTransport.initTcp(io, server_stream);
    var first = try peer.readPacket(allocator, 2048);
    defer first.deinit(allocator);
    var first_publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        first.bytes,
    );
    defer first_publish.deinit(allocator);
    try std.testing.expectEqualStrings("scratch/topic", first_publish.topic);
    try std.testing.expectEqualSlices(u8, &payload, first_publish.payload);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    // TCP writes the retained MQTT prefix and borrowed application payload as
    // one vectored stream operation. The payload therefore does not determine
    // scratch capacity and warm sends need no allocation.
    failing.fail_index = failing.alloc_index;
    connection.allocator = failing.allocator();
    _ = try connection.writePublish("scratch/topic", &payload, .{});
    try std.testing.expectEqual(
        storage,
        connection.write_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        prefix_capacity,
        connection.write_scratch.capacity,
    );
    try std.testing.expect(connection.write_scratch.items.len < payload.len);
    try std.testing.expect(!failing.has_induced_failure);
    var second = try peer.readPacket(allocator, 2048);
    defer second.deinit(allocator);
    var second_publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        second.bytes,
    );
    defer second_publish.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &payload, second_publish.payload);
}

test "MQTT outgoing Packet Identifier allocation failure is transactional" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
        .protocol = .v5,
        .next_packet_id = 65_535,
    };
    defer connection.packet_identifiers.deinit(failing.allocator());

    try std.testing.expectError(
        error.OutOfMemory,
        connection.reserveOutgoingPublish(.at_least_once),
    );
    try std.testing.expectEqual(@as(u16, 65_535), connection.next_packet_id);
    try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.packet_identifiers.count(.outgoing_qos1),
    );
}

test "MQTT variable control writes reuse connection scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    defer connection.write_scratch.deinit(allocator);
    defer connection.clearWritePropertyOverflow();
    var peer = PacketTransport.initTcp(io, server_stream);

    const diagnostic_properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "diagnostic reason",
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "control-writer",
        } },
    };
    const disconnect_properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .server_reference,
            .value = "mqtt.example.test",
        } },
    };
    const auth_properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = "SCRAM-SHA-256",
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = "server-final",
        } },
    };
    const suback_reasons = [_]u8{ 0x00, 0x01 };
    const unsuback_reasons = [_]u8{ 0x00, 0x11 };

    // First pass establishes the maximum output/property capacities used by
    // this sequence. Owned peer packets remain the byte-for-byte oracle for
    // the second pass, independent of codec implementation details.
    try connection.writeConnAck(.{});
    var expected_connack = try peer.readPacket(allocator, 4096);
    defer expected_connack.deinit(allocator);
    try connection.writePubAckWithProperties(
        1,
        0x80,
        &diagnostic_properties,
    );
    var expected_puback = try peer.readPacket(allocator, 4096);
    defer expected_puback.deinit(allocator);
    try connection.writeSubAck(
        2,
        &suback_reasons,
        &diagnostic_properties,
    );
    var expected_suback = try peer.readPacket(allocator, 4096);
    defer expected_suback.deinit(allocator);
    try connection.writeUnsubAck(
        3,
        &unsuback_reasons,
        &diagnostic_properties,
    );
    var expected_unsuback = try peer.readPacket(allocator, 4096);
    defer expected_unsuback.deinit(allocator);
    try connection.writeDisconnectWithProperties(
        0x9c,
        &disconnect_properties,
    );
    var expected_disconnect = try peer.readPacket(allocator, 4096);
    defer expected_disconnect.deinit(allocator);
    try connection.writeAuth(0x18, &auth_properties);
    var expected_auth = try peer.readPacket(allocator, 4096);
    defer expected_auth.deinit(allocator);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try connection.writeConnAck(.{});
    try connection.writePubAckWithProperties(
        1,
        0x80,
        &diagnostic_properties,
    );
    try connection.writeSubAck(
        2,
        &suback_reasons,
        &diagnostic_properties,
    );
    try connection.writeUnsubAck(
        3,
        &unsuback_reasons,
        &diagnostic_properties,
    );
    try connection.writeDisconnectWithProperties(
        0x9c,
        &disconnect_properties,
    );
    try connection.writeAuth(0x18, &auth_properties);
    try std.testing.expect(!failing.has_induced_failure);

    const expected_packets = [_][]const u8{
        expected_connack.bytes,
        expected_puback.bytes,
        expected_suback.bytes,
        expected_unsuback.bytes,
        expected_disconnect.bytes,
        expected_auth.bytes,
    };
    for (expected_packets) |expected| {
        var actual = try peer.readPacket(allocator, 4096);
        defer actual.deinit(allocator);
        try std.testing.expectEqualSlices(u8, expected, actual.bytes);
    }
}

test "MQTT runtime validates DISCONNECT state and sender direction" {
    const zero_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 0,
    } }};
    const nonzero_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 30,
    } }};

    var client = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .endpoint_role = .client,
        .connect_session_expiry = 0,
    };
    try client.validateOutgoingDisconnect(0, &zero_expiry);
    try std.testing.expectError(
        error.InvalidProperty,
        client.validateOutgoingDisconnect(0, &nonzero_expiry),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.validateOutgoingDisconnect(0x89, &.{}),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.writeDisconnectWithProperties(0x89, &.{}),
    );
    // The public writer must fail before touching the deliberately absent
    // transport or allocating/encoding packet storage.
    try std.testing.expectError(
        error.InvalidProperty,
        client.writeDisconnectWithProperties(0, &nonzero_expiry),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        client.validateIncomingDisconnect(.{
            .properties = @constCast(&zero_expiry),
        }),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.validateIncomingDisconnect(.{ .reason_code = 0x04 }),
    );

    var server = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .endpoint_role = .server,
        .connect_session_expiry = 0,
    };
    try std.testing.expectError(
        error.InvalidProperty,
        server.validateOutgoingDisconnect(0, &zero_expiry),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.validateOutgoingDisconnect(0x04, &.{}),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.writeDisconnectWithProperties(0x04, &.{}),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        server.writeDisconnectWithProperties(0, &zero_expiry),
    );
    try server.validateIncomingDisconnect(.{
        .properties = @constCast(&zero_expiry),
    });
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.validateIncomingDisconnect(.{ .reason_code = 0x89 }),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        server.validateIncomingDisconnect(.{
            .properties = @constCast(&nonzero_expiry),
        }),
    );

    client.connect_session_expiry = 10;
    server.connect_session_expiry = 10;
    try client.validateOutgoingDisconnect(0, &nonzero_expiry);
    try server.validateIncomingDisconnect(.{
        .properties = @constCast(&nonzero_expiry),
    });
}

test "MQTT runtime validates AUTH reason sender direction" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var client = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .client,
    };
    try client.validateOutgoingAuthReason(0x18);
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.writeAuth(0x00, &.{}),
    );
    try mqtt.Auth.write(&encoded, allocator, .v5, 0x19, &.{});
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.parseIncomingAuth(encoded.items),
    );

    encoded.clearRetainingCapacity();
    var server = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
    };
    try server.validateOutgoingAuthReason(0x00);
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.writeAuth(0x19, &.{}),
    );
    try mqtt.Auth.write(&encoded, allocator, .v5, 0x00, &.{});
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.parseIncomingAuth(encoded.items),
    );

    encoded.clearRetainingCapacity();
    try mqtt.Auth.write(&encoded, allocator, .v5, 0x18, &.{});
    var client_continue = try client.parseIncomingAuth(encoded.items);
    client_continue.deinit(allocator);
    var server_continue = try server.parseIncomingAuth(encoded.items);
    server_continue.deinit(allocator);
}

test "MQTT runtime enforces Control Packet endpoint direction before I/O" {
    var client = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .client,
    };
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writeConnAck(.{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writeSubAck(1, &.{0x00}, &.{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writeUnsubAck(1, &.{0x00}, &.{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writePingResp(),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.validateIncomingPacketType(.subscribe),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.validateIncomingPacketType(.pingreq),
    );
    const client_incoming = try std.testing.allocator.dupe(
        u8,
        &.{ 0xc0, 0x00 },
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.finishReadPacket(.{
            .bytes = client_incoming,
            .fixed = try mqtt.FixedHeader.parse(client_incoming),
        }),
    );

    var server = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
    };
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.establishClient(.{ .client_id = "invalid-server-connect" }),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.subscribe(&.{.{ .topic_filter = "direction/#" }}, .{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.unsubscribe(&.{"direction/#"}, .{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.writePingReq(),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.validateIncomingPacketType(.connack),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.validateIncomingPacketType(.pingresp),
    );
    const server_incoming = try std.testing.allocator.dupe(
        u8,
        &.{ 0xd0, 0x00 },
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.finishReadPacket(.{
            .bytes = server_incoming,
            .fixed = try mqtt.FixedHeader.parse(server_incoming),
        }),
    );
    const malformed_server_only = try std.testing.allocator.dupe(
        u8,
        &.{ 0xd1, 0x00 },
    );
    try std.testing.expectError(
        error.InvalidFlags,
        server.finishReadPacket(.{
            .bytes = malformed_server_only,
            .fixed = try mqtt.FixedHeader.parse(malformed_server_only),
        }),
    );

    try client.validateOutgoingPacketType(.publish);
    try server.validateOutgoingPacketType(.publish);
    try client.validateIncomingPacketType(.publish);
    try server.validateIncomingPacketType(.publish);
}

test "MQTT runtime enforces incoming maximum packet size on full frame" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var sender = PacketTransport.initTcp(io, client_stream);
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(allocator);
    try mqtt.writePing(&ping, allocator, false);
    try sender.writePacket(ping.items);
    var transport = PacketTransport.initTcp(io, server_stream);

    // A PINGREQ has Remaining Length 0 but a total Control Packet length of 2.
    // MQTT 5's Maximum Packet Size applies to that total length, matching
    // rumqtt's outbound size check and preventing tiny limits from being
    // bypassed by packets with empty variable headers/payloads.
    try std.testing.expectError(
        error.PacketTooLarge,
        transport.readPacket(allocator, 1),
    );
}

test "MQTT runtime PING writes use fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();
    try connection.writePingResp();
    try std.testing.expect(!fail_first.has_induced_failure);

    var received: [mqtt.ping_packet_len]u8 = undefined;
    var buffers = [_][]u8{&received};
    const n = try io.vtable.netRead(
        io.userdata,
        server_stream.socket.handle,
        &buffers,
    );
    try std.testing.expectEqual(received.len, n);
    try mqtt.validatePing(&received, true);
}

test "MQTT runtime property-free acknowledgements use fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();

    // Exercise both MQTT 5 wire lengths, then MQTT 3.1's duplicate PUBREL.
    // Success omits Reason Code and Property Length, while a negative
    // acknowledgement carries the reason.
    try connection.writePubAck(0x1234, 0);
    try connection.writePubRec(0x5678, 0x80);
    try connection.writePubRel(0x9abc, 0);
    try connection.writePubComp(0xdef0, 0x92);
    connection.capabilities.peer_requested_problem_information = false;
    try connection.writePubAckWithProperties(0x2468, 0x80, &.{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "suppressed",
        } },
    });
    connection.protocol = .v3_1;
    try connection.writePubRelWithDup(0x1357, 0, true);
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{
        0x40, 0x02, 0x12, 0x34,
        0x50, 0x03, 0x56, 0x78,
        0x80, 0x62, 0x02, 0x9a,
        0xbc, 0x70, 0x03, 0xde,
        0xf0, 0x92, 0x40, 0x03,
        0x24, 0x68, 0x80, 0x6a,
        0x02, 0x13, 0x57,
    };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT runtime property-free DISCONNECT uses fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();
    try connection.disconnect(0x8d);
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{ 0xe0, 0x01, 0x8d };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT runtime property-free AUTH uses fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .capabilities = .{ .peer_requested_problem_information = false },
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();

    try connection.writeAuth(0, &.{});
    try connection.writeAuth(0x18, &.{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "suppressed",
        } },
    });
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{
        0xf0, 0x00,
        0xf0, 0x02,
        0x18, 0x00,
    };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT runtime bare CONNACK uses fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();

    // Rejected v5 connections do not advertise negotiated capabilities; v3
    // has no CONNACK property field at all. Both forms must remain writable
    // even when the general allocator cannot provide a scratch allocation.
    try connection.writeConnAck(.{ .reason_code = 0x80 });
    connection.protocol = .v3_1_1;
    try connection.writeConnAck(.{ .reason_code = 0x05 });
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{
        0x20, 0x03, 0x00, 0x80,
        0x00, 0x20, 0x02, 0x00,
        0x05,
    };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT server applies the effective inbound QoS limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer peer.close(io);
    const server_stream = try listener.accept(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, server_stream),
        .protocol = .v3_1_1,
    };
    defer connection.close();
    try connection.writeConnAck(.{ .max_outgoing_inflight = 1 });
    try std.testing.expectEqual(
        @as(u16, 1),
        connection.max_incoming_inflight,
    );

    connection.protocol = .v5;
    try connection.writeConnAck(.{
        .properties = &.{.{ .two_byte = .{
            .id = .receive_maximum,
            .value = 2,
        } }},
        .max_outgoing_inflight = 3,
    });
    try std.testing.expectEqual(
        @as(u16, 2),
        connection.max_incoming_inflight,
    );

    try connection.writeConnAck(.{
        .max_outgoing_inflight = std.math.maxInt(u16),
    });
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        connection.max_incoming_inflight,
    );
}

test "MQTT connection enforces incoming receive maximum" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .max_incoming_inflight = 1,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);

    const first = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/one",
        .packet_id = 10,
        .payload = "first",
    };
    _ = try connection.recordIncomingPublish(first);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    var retry = first;
    retry.dup = true;
    _ = try connection.recordIncomingPublish(retry);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    try std.testing.expectError(error.ReceiveMaximumExceeded, connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/two",
        .packet_id = 11,
        .payload = "second",
    }));

    connection.completeIncomingPublish(.puback, 10);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/two",
        .packet_id = 11,
        .payload = "second",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
}

test "MQTT incoming PUBLISH commits QoS and Topic Alias transactionally" {
    const allocator = std.testing.allocator;
    const alias_property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
        .max_incoming_inflight = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer connection.packet_identifiers.deinit(allocator);
    defer connection.clearIncomingTopicAliases();
    try (try connection.ensureIncomingTopicAliases()).put(
        allocator,
        1,
        "old/topic",
    );

    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "seed",
        .packet_id = 17,
        .payload = "seed",
    });
    var conflicting = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "new/topic",
        .packet_id = 17,
        .properties = @constCast(&alias_property),
        .payload = "conflict",
    };
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        connection.commitIncomingPublish(&conflicting),
    );
    try std.testing.expectEqualStrings(
        "old/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    var over_limit = conflicting;
    over_limit.packet_id = 18;
    try std.testing.expectError(
        error.ReceiveMaximumExceeded,
        connection.commitIncomingPublish(&over_limit),
    );
    try std.testing.expectEqualStrings(
        "old/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    connection.completeIncomingPublish(.pubcomp, 17);
    // Keep sparse identifier capacity available so the only allocation in the
    // commit is the Topic Alias replacement after QoS registration.
    _ = try connection.packet_identifiers.add(
        allocator,
        19,
        .incoming_qos1,
    );
    try std.testing.expect(connection.packet_identifiers.remove(
        19,
        .incoming_qos1,
    ));
    var fail_alias = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    connection.allocator = fail_alias.allocator();
    var allocation_failure = conflicting;
    allocation_failure.packet_id = 19;
    try std.testing.expectError(
        error.OutOfMemory,
        connection.commitIncomingPublish(&allocation_failure),
    );
    try std.testing.expectEqualStrings(
        "old/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    try std.testing.expect(!connection.packet_identifiers.contains(
        19,
        .incoming_qos1,
    ));
}

test "MQTT connection keeps QoS2 receive slot until PUBCOMP" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .max_incoming_inflight = 1,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);

    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "receive/qos2",
        .packet_id = 20,
        .payload = "first",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
    try connection.validateIncomingPubRel(20);
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.validateIncomingPubRel(21));
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/reuse",
        .packet_id = 20,
        .payload = "reuse",
    }));

    connection.completeIncomingPublish(.puback, 20);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
    try std.testing.expectError(error.ReceiveMaximumExceeded, connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "receive/blocked",
        .packet_id = 21,
        .payload = "blocked",
    }));

    connection.completeIncomingPublish(.pubcomp, 20);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.validateIncomingPubRel(20));
    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "receive/after-comp",
        .packet_id = 21,
        .payload = "ok",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    connection.completeIncomingPubRec(21, 0x10); // No matching subscribers still completes via PUBREL/PUBCOMP.
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
    try connection.validateIncomingPubRel(21);
    connection.completeIncomingPubRec(21, 0x80);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.validateIncomingPubRel(21));
}

test "MQTT connection enforces negotiated subscribe capabilities" {
    const exact = [_]mqtt.Subscription{.{ .topic_filter = "sensors/temp" }};
    const wildcard = [_]mqtt.Subscription{.{ .topic_filter = "sensors/+" }};
    const shared = [_]mqtt.Subscription{.{ .topic_filter = "$share/workers/sensors/temp" }};
    const sub_id = [_]mqtt.Property{.{ .varint = .{ .id = .subscription_identifier, .value = 1 } }};

    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .capabilities = .{
            .peer_wildcard_subscription_available = false,
            .peer_subscription_identifier_available = false,
            .peer_shared_subscription_available = false,
        },
    };

    try connection.validateOutgoingSubscribe(&exact, &.{});
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&wildcard, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&shared, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&exact, &sub_id));

    connection.capabilities.local_wildcard_subscription_available = false;
    connection.capabilities.local_subscription_identifier_available = false;
    connection.capabilities.local_shared_subscription_available = false;
    try connection.validateIncomingSubscribe(&exact, &.{});
    try std.testing.expectError(error.WildcardSubscriptionsNotSupported, connection.validateIncomingSubscribe(&wildcard, &.{}));
    try std.testing.expectError(error.SharedSubscriptionsNotSupported, connection.validateIncomingSubscribe(&shared, &.{}));
    try std.testing.expectError(error.SubscriptionIdentifiersNotSupported, connection.validateIncomingSubscribe(&exact, &sub_id));
}

test "MQTT connection rejects topic aliases beyond negotiated maximum" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer connection.clearOutgoingTopicAliases();

    try std.testing.expectError(error.InvalidProperty, connection.publish("topic", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }},
    }));
    try std.testing.expectError(error.InvalidTopic, connection.publish("", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }},
    }));
    try connection.validateOutgoingTopicAlias("topic", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try connection.prepareOutgoingTopicAliasCommit("topic", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try connection.validateOutgoingTopicAlias("", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});

    var incoming = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "topic",
        .packet_id = null,
        .properties = @constCast(&[_]mqtt.Property{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }}),
        .payload = "payload",
    };
    try std.testing.expectError(error.TopicAliasInvalid, connection.applyIncomingTopicAlias(&incoming));
}

test "MQTT connection automatically establishes and reuses outgoing aliases" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 2,
    };
    defer connection.clearOutgoingTopicAliases();

    var first_properties: std.ArrayList(mqtt.Property) = .empty;
    defer first_properties.deinit(allocator);
    const first_topic = try connection.prepareAutomaticTopicAlias(
        "alias/topic",
        &first_properties,
    );
    try std.testing.expectEqualStrings("alias/topic", first_topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        first_properties.items,
    ));
    try connection.prepareOutgoingTopicAliasCommit(
        first_topic,
        first_properties.items,
    );

    var repeated_properties: std.ArrayList(mqtt.Property) = .empty;
    defer repeated_properties.deinit(allocator);
    const repeated_topic = try connection.prepareAutomaticTopicAlias(
        "alias/topic",
        &repeated_properties,
    );
    try std.testing.expectEqualStrings("", repeated_topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        repeated_properties.items,
    ));

    var second_properties: std.ArrayList(mqtt.Property) = .empty;
    defer second_properties.deinit(allocator);
    const second_topic = try connection.prepareAutomaticTopicAlias(
        "second/topic",
        &second_properties,
    );
    try std.testing.expectEqualStrings("second/topic", second_topic);
    try std.testing.expectEqual(@as(?u16, 2), mqtt.topicAlias(
        second_properties.items,
    ));
}

test "MQTT Session PUBLISH projects Topic Alias per Network Connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const transmission = @import("session/mod.zig").Transmission{
        .publish = .{
            .topic = "durable/alias",
            .payload = "payload",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 7,
            .properties = &.{.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 60,
            } }},
            .message_expiry_interval = 30,
        },
    };

    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.close();

    try connection.writeSessionTransmission(
        transmission,
        .exactly_once,
    );
    try std.testing.expect(connection.write_property_overflow == null);
    var first_packet = try peer.readPacket(allocator, 4096);
    defer first_packet.deinit(allocator);
    var first = try mqtt.Publish.parse(allocator, .v5, first_packet.bytes);
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("durable/alias", first.topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        first.properties,
    ));
    try std.testing.expectEqual(@as(?u32, 30), mqtt.messageExpiryInterval(
        first.properties,
    ));
    try std.testing.expect(connection.write_scratch.items.len <
        first_packet.bytes.len);

    // The next delivery reuses the encoded prefix, stages its small property
    // set on the stack, and needs no Topic Alias map growth, so the complete
    // write succeeds when every new allocation is rejected.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    try connection.writeSessionTransmission(
        transmission,
        .exactly_once,
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(connection.write_property_overflow == null);
    var second_packet = try peer.readPacket(allocator, 4096);
    defer second_packet.deinit(allocator);
    var second = try mqtt.Publish.parse(
        allocator,
        .v5,
        second_packet.bytes,
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("", second.topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        second.properties,
    ));
    try std.testing.expectEqualStrings(
        "durable/alias",
        transmission.publish.topic,
    );
    try std.testing.expect(mqtt.topicAlias(
        transmission.publish.properties,
    ) == null);

    const fresh_client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var fresh_peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer fresh_peer.close(allocator);
    var fresh = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, fresh_client_stream),
        .protocol = .v5,
        .endpoint_role = .client,
        .peer_topic_alias_maximum = 1,
    };
    defer fresh.close();
    try fresh.writeClientSessionTransmission(transmission);
    var fresh_packet = try fresh_peer.readPacket(allocator, 4096);
    defer fresh_packet.deinit(allocator);
    var fresh_publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        fresh_packet.bytes,
    );
    defer fresh_publish.deinit(allocator);
    try std.testing.expectEqualStrings("durable/alias", fresh_publish.topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        fresh_publish.properties,
    ));
}

test "MQTT Session PUBLISH falls back when alias form exceeds packet limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);

    const transmission = @import("session/mod.zig").Transmission{
        .publish = .{
            .topic = "a",
            .payload = "x",
            .qos = .at_least_once,
            .retain = false,
            .dup = false,
            .packet_id = 9,
            .properties = &.{},
            .message_expiry_interval = null,
        },
    };
    var exact: std.ArrayList(u8) = .empty;
    defer exact.deinit(allocator);
    try transmission.publish.write(&exact, allocator, .v5);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .peer_topic_alias_maximum = 1,
        .peer_max_packet_size = exact.items.len,
    };
    defer connection.close();
    try (try connection.ensureOutgoingTopicAliases()).put(allocator, 1, "a");

    try connection.writeSessionTransmission(transmission, .exactly_once);
    try std.testing.expectEqual(@as(usize, 1), connection.outgoingTopicAliasCount());
    try std.testing.expectEqualStrings(
        "a",
        connection.outgoingTopicAlias(1).?,
    );
    var packet = try peer.readPacket(allocator, 4096);
    defer packet.deinit(allocator);
    var publish = try mqtt.Publish.parse(allocator, .v5, packet.bytes);
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings("a", publish.topic);
    try std.testing.expect(mqtt.topicAlias(publish.properties) == null);

    try std.testing.expectError(
        error.InvalidProperty,
        connection.writeClientSessionTransmission(.{ .publish = .{
            .topic = "must/remain/canonical",
            .payload = "x",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 10,
            .properties = &.{.{ .two_byte = .{
                .id = .topic_alias,
                .value = 1,
            } }},
            .message_expiry_interval = null,
        } }),
    );
    try std.testing.expect(connection.isUsable());
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.outgoingTopicAliasCount(),
    );
}

test "MQTT Session PUBLISH alias allocation failure is pre-wire" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .client,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.close();

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.writeClientSessionTransmission(.{ .publish = .{
            .topic = "allocation/failure",
            .payload = "payload",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 11,
            .properties = &.{},
            .message_expiry_interval = null,
        } }),
    );
    try std.testing.expect(connection.isUsable());
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.outgoingTopicAliasCount(),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.write_scratch.items.len);
    try std.testing.expectError(
        error.Timeout,
        peer.readPacketWithDeadline(
            allocator,
            4096,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
}

test "MQTT transport write failure retires connection Topic Alias state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.close();
    const alias_property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};

    // A local full shutdown makes the first socket write fail deterministically.
    // Alias ownership was prepared before that attempt, but its wire outcome
    // is unknowable and therefore the connection may never use it again.
    try connection.transport.shutdown();
    const first_failed = blk: {
        _ = connection.writePublish(
            "retired/alias",
            "payload",
            .{ .properties = &alias_property },
        ) catch break :blk true;
        break :blk false;
    };
    try std.testing.expect(first_failed);
    try std.testing.expect(!connection.isUsable());
    try std.testing.expectEqualStrings(
        "retired/alias",
        connection.outgoingTopicAlias(1).?,
    );

    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writePublish(
            "",
            "must not reach the wire",
            .{ .properties = &alias_property },
        ),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.readPingReq(),
    );
}

test "MQTT connection supports aliases above the former fixed table" {
    const allocator = std.testing.allocator;
    const maximum_alias = std.math.maxInt(u16);
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = maximum_alias,
        .incoming_topic_alias_maximum = maximum_alias,
    };
    defer connection.clearTopicAliases();

    const property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = maximum_alias,
    } }};
    try connection.validateOutgoingTopicAlias("large/alias", &property);
    try connection.prepareOutgoingTopicAliasCommit(
        "large/alias",
        &property,
    );
    try connection.validateOutgoingTopicAlias("", &property);

    var registered = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "incoming/large/alias",
        .packet_id = null,
        .properties = @constCast(&property),
        .payload = "first",
    };
    try connection.applyIncomingTopicAlias(&registered);
    var reused = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "",
        .packet_id = null,
        .properties = @constCast(&property),
        .payload = "second",
    };
    try connection.applyIncomingTopicAlias(&reused);
    try std.testing.expectEqualStrings("incoming/large/alias", reused.topic);
}

test "MQTT runtime advertises the configured topic alias maximum" {
    const allocator = std.testing.allocator;

    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{}, 99);
    try std.testing.expectEqual(
        @as(?u16, 99),
        mqtt.topicAliasMaximum(properties.items),
    );

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{.{ .two_byte = .{
        .id = .topic_alias_maximum,
        .value = 8,
    } }}, 99);
    try std.testing.expectEqual(@as(usize, 0), properties.items.len);

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(
        &properties,
        allocator,
        &.{},
        std.math.maxInt(u16),
    );
    try std.testing.expectEqual(
        @as(?u16, std.math.maxInt(u16)),
        mqtt.topicAliasMaximum(properties.items),
    );

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 0), properties.items.len);
}

test "MQTT connection enforces peer publish capabilities" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .capabilities = .{
            .peer_maximum_qos = .at_most_once,
            .peer_retain_available = false,
        },
    };

    try std.testing.expectError(error.InvalidQoS, connection.publish("topic", "payload", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidProperty, connection.publish("topic", "payload", .{ .retain = true }));

    connection.capabilities.peer_retain_available = true;
    connection.capabilities.outgoing_retain_enabled = false;
    try std.testing.expectError(
        error.InvalidProperty,
        connection.publish("topic", "locally blocked", .{ .retain = true }),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        connection.writeClientSessionTransmission(.{ .publish = .{
            .topic = "topic",
            .payload = "locally blocked",
            .qos = .at_most_once,
            .retain = true,
            .dup = false,
            .packet_id = 1,
            .properties = &.{},
            .message_expiry_interval = null,
        } }),
    );

    connection.capabilities.local_maximum_qos = .at_most_once;
    try std.testing.expectError(error.QoSNotSupported, connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "qos/in",
        .packet_id = 7,
        .payload = "blocked",
    }));

    connection.capabilities.local_maximum_qos = .exactly_once;
    connection.capabilities.local_retain_available = false;
    try std.testing.expectError(error.RetainNotSupported, connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "retained/in",
        .packet_id = null,
        .payload = "blocked",
    }));
    try connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "normal/in",
        .packet_id = null,
        .payload = "ok",
    });
}

test "MQTT connection enforces PUBLISH subscription identifier direction" {
    const properties = [_]mqtt.Property{
        .{ .varint = .{
            .id = .subscription_identifier,
            .value = 7,
        } },
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    };
    const publish_packet = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "direction/topic",
        .packet_id = null,
        .properties = @constCast(&properties),
        .payload = "payload",
    };

    var server = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
        .incoming_topic_alias_maximum = 1,
    };
    defer server.clearIncomingTopicAliases();
    try std.testing.expectError(
        error.InvalidProperty,
        server.validateIncomingPublishCapabilities(publish_packet),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.incomingTopicAliasCount(),
    );
    try std.testing.expectEqual(@as(u16, 0), server.incoming_inflight);
    try server.validatePublishPropertyDirection(properties[0..], .outgoing);

    var client = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .client,
    };
    try client.validateIncomingPublishCapabilities(publish_packet);
    try std.testing.expectError(
        error.InvalidProperty,
        client.writePublish(
            "direction/topic",
            "payload",
            .{ .properties = properties[0..] },
        ),
    );
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try std.testing.expectEqual(@as(usize, 0), client.write_scratch.items.len);
    try std.testing.expectError(
        error.InvalidProperty,
        client.writeClientSessionTransmission(.{ .publish = .{
            .topic = "direction/topic",
            .payload = "payload",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 1,
            .properties = properties[0..],
            .message_expiry_interval = null,
        } }),
    );
    try std.testing.expectEqual(@as(usize, 0), client.write_scratch.items.len);

    server.protocol = .v3_1_1;
    try server.validatePublishPropertyDirection(properties[0..], .incoming);
}

test "MQTT client applies configured peer publish defaults" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "peer-default-client",
        .limits = .{ .max_packet_size = 4096 },
        .peer_maximum_qos = .at_most_once,
        .peer_retain_available = false,
    });
    defer client.close();

    try std.testing.expectEqual(mqtt.QoS.at_most_once, client.peerMaximumQoS());
    try std.testing.expect(!client.peerRetainAvailable());
    try std.testing.expectError(error.InvalidQoS, client.publish("peer/defaults", "qos1", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidProperty, client.publish("peer/defaults", "retain", .{ .retain = true }));
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT runtime surfaces negative publish acknowledgements" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
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
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("negative/topic", publish.publish.topic);
            try std.testing.expectEqualStrings("reject me", publish.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, publish.publish.qos);
            try accepted.connection.writePubAckWithProperties(publish.publish.packet_id.?, 0x80, &.{
                .{ .utf8 = .{ .id = .reason_string, .value = "negative ack" } },
                .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "puback-negative" } },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "negative-ack-client",
        .limits = .{ .max_packet_size = 4096 },
    });
    defer client.close();

    try std.testing.expectError(error.PublishRefused, client.publish("negative/topic", "reject me", .{ .qos = .at_least_once }));

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), accepted: *AcceptedClient) Error!void {
            if (std.mem.eql(u8, accepted.connect.connect.client_id, "mqtt-one")) {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(accepted.connection.allocator);
                if (!std.mem.eql(u8, publish.publish.payload, "one")) return error.UnexpectedPacket;
                try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
                return;
            }
            if (std.mem.eql(u8, accepted.connect.connect.client_id, "mqtt-two")) {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(accepted.connection.allocator);
                if (!std.mem.eql(u8, publish.publish.payload, "two")) return error.UnexpectedPacket;
                try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
                return;
            }
            return error.UnexpectedPacket;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{ .protocol = .v5 }) catch |err| {
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
        client_id: []const u8,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .protocol = .v5,
                .client_id = task.client_id,
                .limits = .{ .max_packet_size = 4096 },
            });
            defer client.close();
            try client.publish("async/topic", task.payload, .{ .qos = .at_least_once });
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .client_id = "mqtt-one", .payload = "one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .client_id = "mqtt-two", .payload = "two" },
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

test "MQTT broker event borrows caller storage for a complete TCP acknowledgement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .keep_alive_seconds = 1,
    };
    defer connection.close();

    var encoded = [_]u8{ 0x40, 0x02, 0x00, 0x07 };
    try peer.writePacket(&encoded);
    var storage: [16]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    var event = try connection.readBrokerEventWithKeepAliveInto(&storage);
    defer event.deinit(failing.allocator());

    try std.testing.expect(event == .puback);
    try std.testing.expect(!event.puback.packet.owns_bytes);
    try std.testing.expectEqual(storage[0..].ptr, event.puback.packet.bytes.ptr);
    try std.testing.expectEqual(@as(u16, 7), event.puback.ack.packet_id);
    try std.testing.expect(!failing.has_induced_failure);
}

test "MQTT broker caller-output event transfers ownership and preserves output on error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .keep_alive_seconds = 1,
    };
    defer connection.close();

    var storage: [1]u8 = undefined;
    var event: BrokerEvent = undefined;
    var puback = [_]u8{ 0x40, 0x02, 0x00, 0x07 };
    try peer.writePacket(&puback);
    try connection.readBrokerEventWithKeepAliveIntoPrefixedOut(
        &storage,
        32,
        &event,
    );
    try std.testing.expect(event == .puback);
    try std.testing.expect(event.puback.packet.owns_bytes);
    try std.testing.expectEqual(@as(u16, 32), event.puback.packet.prefix_len);
    try std.testing.expect(event.puback.packet.prefixedAllocation() != null);
    try std.testing.expectEqual(@as(u16, 7), event.puback.ack.packet_id);
    event.deinit(allocator);

    var sentinel_bytes = [_]u8{ 0xc0, 0x00 };
    event = .{ .pingreq = .{
        .bytes = &sentinel_bytes,
        .fixed = .{
            .packet_type = .pingreq,
            .flags = 0,
            .remaining_len = 0,
            .header_len = 2,
        },
        .owns_bytes = false,
    } };
    var malformed_subscribe =
        [_]u8{ 0x82, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p', 0x40 };
    try peer.writePacket(&malformed_subscribe);
    try std.testing.expectError(
        error.MalformedSubscriptionOptions,
        connection.readBrokerEventWithKeepAliveIntoPrefixedOut(
            &storage,
            32,
            &event,
        ),
    );
    try std.testing.expect(event == .pingreq);
    try std.testing.expectEqual(sentinel_bytes[0..].ptr, event.pingreq.bytes.ptr);
    event.deinit(allocator);
}

test "MQTT serveUntil isolates CONNECT errors and reuses its worker" {
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
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        stage: ServeErrorStage = .connection,

        fn observe(context_ptr: *anyopaque, event: ServeErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.stage = event.stage;
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.io);
        }
    };
    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        handled: std.atomic.Value(usize) = .init(0),

        fn handle(
            self: *@This(),
            accepted: *AcceptedClient,
        ) Error!void {
            var event = try accepted.connection.readBrokerEvent();
            defer event.deinit(accepted.connection.allocator);
            if (event != .pingreq) return error.UnexpectedPacket;
            try accepted.connection.writePingResp();
            _ = self.handled.fetchAdd(1, .release);
            if (std.mem.eql(
                u8,
                accepted.connect.connect.client_id,
                "mqtt-supervisor-stop",
            )) {
                self.shutdown.set(self.io);
            }
        }
    };
    const Shared = struct {
        server: *Server,
        shutdown: std.Io.Event = .unset,
        observer: Observer,
        context: Context,
        err: ?anyerror = null,

        fn init(server_ptr: *Server, io_value: std.Io) @This() {
            var shared: @This() = undefined;
            shared.server = server_ptr;
            shared.shutdown = .unset;
            shared.observer = .{ .io = io_value };
            shared.context = .{
                .io = io_value,
                .shutdown = &shared.shutdown,
            };
            shared.err = null;
            return shared;
        }

        fn run(self: *@This()) void {
            self.context.shutdown = &self.shutdown;
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                .{ .protocol = .v5 },
                .{
                    .shutdown = &self.shutdown,
                    .error_observer = .{
                        .context = &self.observer,
                        .observe = Observer.observe,
                    },
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared.init(&server, io);
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    const malformed = try server.address().connect(io, .{ .mode = .stream });
    const malformed_bytes = [_]u8{ 0xc0, 0x00 };
    var malformed_writer = malformed.writer(io, &.{});
    try malformed_writer.interface.writeAll(&malformed_bytes);
    malformed.close(io);
    try shared.observer.observed.wait(io);
    try std.testing.expectEqual(ServeErrorStage.accept, shared.observer.stage);

    for ([_][]const u8{ "mqtt-supervisor-one", "mqtt-supervisor-stop" }) |client_id| {
        var client = try Client.connect(
            allocator,
            io,
            server.address(),
            .{ .protocol = .v5, .client_id = client_id },
        );
        defer client.close();
        try client.ping();
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.handled.load(.acquire),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        shared.observer.count.load(.acquire),
    );
}

test {
    _ = @import("runtime/acknowledgement/deadline_tests.zig");
    _ = @import("runtime/acknowledgement/subscribe_tests.zig");
    _ = @import("runtime/acknowledgement/reconnect_tests.zig");
    _ = @import("runtime/acknowledgement/byte_limit_tests.zig");
    _ = @import("runtime/acceptance_tests.zig");
}

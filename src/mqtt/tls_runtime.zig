const std = @import("std");
const mqtt_runtime = @import("runtime.zig");
const redirect = @import("redirect.zig");
const http1_runtime = @import("../http1/mod.zig").runtime;
const socket_options = @import("../internal/socket_options.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const network_endpoint = @import("runtime/network_endpoint.zig");
const deadline_policy = @import("../internal/deadline.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const vail = @import("vail");

const net = std.Io.net;

pub const ServerIdentity = vail.tls.auth.ServerIdentity;
pub const ServerSigner = vail.tls.auth.Signer;
pub const CipherSuite = vail.tls.cipher_suite.Suite;
pub const ClientCertificateVerifier = vail.tls.auth.ClientVerifier;
pub const ClientAuthPolicy = vail.tls.client_auth.ServerPolicy;
pub const ClientAuthRequirement = vail.tls.client_auth.Requirement;
pub const ClientIdentity = vail.tls.client_auth.ClientIdentity;

/// Native MQTT-over-TLS listener using vail's TLS 1.3 primitives.
///
/// Each accepted socket completes its TLS handshake before the shared MQTT
/// runtime reads CONNECT. `Server` borrows the configured certificate-chain
/// slices while it remains able to accept; established connections retain
/// traffic keys, not certificate or signer references.
pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,
    limits: mqtt_runtime.Limits,
    tls: tls_stream.ServerOptions,
    tcp_nodelay: bool,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: ListenOptions,
    ) mqtt_runtime.Error!Server {
        try options.identity.validate();
        try mqtt_runtime.validateProxyPolicy(options.limits);
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
                .alpn_protocols = options.alpn_protocols,
            },
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(
        self: *Server,
        options: mqtt_runtime.AcceptOptions,
    ) mqtt_runtime.Error!mqtt_runtime.AcceptedClient {
        var pending = try self.acceptPending(options);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    /// Accept TCP, then bound PROXY parsing, TLS, MQTT CONNECT, and CONNACK
    /// policy with one caller-owned awake-clock deadline.
    pub fn acceptWithDeadline(
        self: *Server,
        options: mqtt_runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.AcceptedClient {
        var pending = try self.acceptPendingWithDeadline(options, deadline);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: mqtt_runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.AcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        var pending = try self.acceptPendingWithTimeout(options, timeout);
        errdefer pending.deinit(self.allocator);
        return pending.finish(options);
    }

    /// Complete transport setup and parse CONNECT without sending CONNACK.
    /// Stateful brokers use this to apply Session and authorization policy
    /// consistently across TCP, TLS, WS and WSS listeners.
    pub fn acceptPending(
        self: *Server,
        options: mqtt_runtime.AcceptOptions,
    ) mqtt_runtime.Error!mqtt_runtime.PendingAcceptedClient {
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamPendingMaybeBefore(stream, options, null);
    }

    pub fn acceptPendingWithDeadline(
        self: *Server,
        options: mqtt_runtime.AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.PendingAcceptedClient {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamPendingMaybeBefore(
            stream,
            options,
            deadline,
        );
    }

    pub fn acceptPendingWithTimeout(
        self: *Server,
        options: mqtt_runtime.AcceptOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.PendingAcceptedClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const stream = try self.listener.accept(self.io);
        return self.acceptStreamPendingMaybeBefore(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamPendingMaybeBefore(
        self: *Server,
        stream: net.Stream,
        options: mqtt_runtime.AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.PendingAcceptedClient {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        var proxy_metadata = try mqtt_runtime.readProxyMetadata(
            self.allocator,
            self.io,
            stream,
            self.limits,
            deadline,
        );
        errdefer if (proxy_metadata) |*metadata| metadata.deinit();
        if (self.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
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

        var connection = mqtt_runtime.Connection.initTlsServer(
            self.allocator,
            tls_connection,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        errdefer connection.close();
        if (proxy_metadata) |metadata| {
            connection.attachProxyMetadata(metadata);
            proxy_metadata = null;
        }
        return if (deadline) |absolute|
            connection.acceptPendingWithDeadline(options, absolute)
        else
            connection.acceptPending(options);
    }

    pub fn pendingSource(self: *Server) mqtt_runtime.PendingSource {
        return .{
            .context = self,
            .accept_pending = struct {
                fn call(
                    context: *anyopaque,
                    options: mqtt_runtime.AcceptOptions,
                ) anyerror!mqtt_runtime.PendingAcceptedClient {
                    const server: *Server = @ptrCast(@alignCast(context));
                    return server.acceptPending(options);
                }
            }.call,
        };
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *mqtt_runtime.AcceptedClient,
        ) mqtt_runtime.Error!void,
        max_connections: usize,
        options: mqtt_runtime.AcceptOptions,
    ) mqtt_runtime.AsyncServeError!mqtt_runtime.ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(
            ?anyerror,
            max_connections,
        );
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var accepted = try self.accept(options);
            errdefer accepted.deinit(self.allocator);
            const task = ServerTask(HandlerContext){
                .accepted = accepted,
                .context = context,
                .handler = handler,
                .result = result,
                .allocator = self.allocator,
            };
            group.async(
                self.io,
                ServerTask(HandlerContext).run,
                .{task},
            );
        }

        try group.await(self.io);
        return .{
            .allocator = self.allocator,
            .errors = results,
        };
    }

    pub fn serveUntil(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *mqtt_runtime.AcceptedClient,
        ) mqtt_runtime.Error!void,
        max_connections: usize,
        accept_options: mqtt_runtime.AcceptOptions,
        serve_options: mqtt_runtime.ServeUntilOptions,
    ) anyerror!void {
        return mqtt_runtime.serveSourceUntil(
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

pub const ListenOptions = struct {
    /// Certificate chain storage remains borrowed by `Server` and must outlive
    /// the listener. Signer key material is copied into the listener value.
    identity: ServerIdentity,
    limits: mqtt_runtime.Limits = .{},
    cipher_suites: []const CipherSuite =
        &vail.tls.cipher_suite.default_preference,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget for TLS setup before MQTT CONNECT parsing.
    tls_handshake_timeout: ?std.Io.Duration = null,
    /// Request and verify a TLS 1.3 client certificate. `required` is the
    /// default within the policy; use `.optional` to retain anonymous clients.
    client_auth: ?ClientAuthPolicy = null,
    /// Supported ALPN protocols. A non-empty list requires the client to offer
    /// one of these protocols and exposes the selection on Connection.
    alpn_protocols: []const []const u8 = &.{},
    /// MQTT control packets are latency sensitive, matching the client
    /// default. Disable this when deliberate TCP batching is preferred.
    tcp_nodelay: bool = true,
};

fn ServerTask(comptime HandlerContext: type) type {
    return struct {
        accepted: mqtt_runtime.AcceptedClient,
        context: *HandlerContext,
        handler: *const fn (
            *HandlerContext,
            *mqtt_runtime.AcceptedClient,
        ) mqtt_runtime.Error!void,
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

/// Native MQTT-over-TLS client.
///
/// TLS setup is shared with HTTP/1 and WSS, including operating-system roots,
/// explicit CA bundles, hostname verification, and truncation policy. Once the
/// handshake succeeds, all MQTT CONNECT/CONNACK and QoS state is handled by
/// the same `mqtt.runtime.Connection` used for cleartext TCP and WebSocket.
pub const Client = struct {
    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(
            io,
            host_name,
            port,
            options.mqtt.network_connect_timeout,
        );
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            host,
            options,
        );
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
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
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
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

    /// Resolve, establish TLS, and negotiate MQTT under one caller-owned
    /// deadline. Configured network, TLS, and MQTT phase limits remain stricter
    /// upper bounds when they expire before the outer timestamp.
    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const host_name = try net.HostName.init(host);
        const network_deadline = try deadline_policy.capTimeout(
            io,
            deadline,
            options.mqtt.network_connect_timeout,
        );
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            network_deadline,
        );
        return connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            host,
            options,
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
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

    pub fn connectAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectAddressWithConnAck(
            allocator,
            io,
            address,
            tls_host,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectAddressWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectAddressAttempt(
            allocator,
            io,
            address,
            tls_host,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectAddressAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const stream = try tcp_connect.ip(
            io,
            address,
            options.mqtt.network_connect_timeout,
        );
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            options,
        );
    }

    pub fn connectAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectAddressWithConnAckWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAddressWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectAddressWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAddressWithConnAckWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAddressAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const network_deadline = try deadline_policy.capTimeout(
            io,
            deadline,
            options.mqtt.network_connect_timeout,
        );
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            network_deadline,
        );
        return connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            tls_host,
            options,
            deadline,
        );
    }

    pub fn connectAddressAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        var target = redirect.parse(
            allocator,
            uri_text,
            .tls,
        ) catch |err| return switch (err) {
            error.UnsupportedRedirectScheme => error.UnsupportedScheme,
            error.InvalidServerReference => error.InvalidUri,
            else => err,
        };
        defer target.deinit();
        const tls_host = network_endpoint.tlsHost(&target) catch
            return error.InvalidUri;
        const stream = network_endpoint.connectTarget(
            io,
            &target,
            .tls,
            options.mqtt.network_connect_timeout,
        ) catch |err| return switch (err) {
            error.UnsupportedRedirectScheme => error.UnsupportedScheme,
            error.InvalidServerReference => error.InvalidUri,
            else => err,
        };
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            options,
        );
    }

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
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
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
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
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithConnAckWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        var target = redirect.parse(
            allocator,
            uri_text,
            .tls,
        ) catch |err| return switch (err) {
            error.UnsupportedRedirectScheme => error.UnsupportedScheme,
            error.InvalidServerReference => error.InvalidUri,
            else => err,
        };
        defer target.deinit();
        const tls_host = network_endpoint.tlsHost(&target) catch
            return error.InvalidUri;
        const network_deadline = try deadline_policy.capTimeout(
            io,
            deadline,
            options.mqtt.network_connect_timeout,
        );
        const stream = network_endpoint.connectTargetWithDeadline(
            io,
            &target,
            .tls,
            network_deadline,
        ) catch |err| return switch (err) {
            error.UnsupportedRedirectScheme => error.UnsupportedScheme,
            error.InvalidServerReference => error.InvalidUri,
            else => err,
        };
        return connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            tls_host,
            options,
            deadline,
        );
    }

    pub fn connectUriAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Follow MQTT 5 redirect CONNACKs while preserving TLS verification.
    /// Each hop derives a fresh SNI/hostname identity from its Server
    /// Reference; trust configuration and optional client identity are reused.
    pub fn connectUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        policy: redirect.Policy,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        if (options.mqtt.protocol != .v5) {
            return error.UnsupportedRedirectScheme;
        }
        var chain = redirect.Chain.init(allocator, policy);
        defer chain.deinit();
        var current_uri = try allocator.dupe(u8, uri_text);
        defer allocator.free(current_uri);
        try chain.recordInitial(current_uri, .tls);

        while (true) {
            var target = try redirect.parse(allocator, current_uri, .tls);
            defer target.deinit();
            if (target.transport != .tls) return error.UnsupportedRedirectScheme;
            var attempt = try connectUriAttempt(
                allocator,
                io,
                target.uri,
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

pub const ConnectOptions = struct {
    mqtt: mqtt_runtime.ConnectOptions,
    tls: http1_runtime.TlsClientOptions = .{},
    /// Select the vail TLS 1.3 stream client and answer CertificateRequest.
    /// The identity storage only needs to outlive the synchronous connect call.
    client_identity: ?ClientIdentity = null,
    /// Server trust policy for the vail path. When omitted, the runtime maps
    /// `tls.ca_bundle`/system roots and hostname verification to vail's X.509
    /// verifier, preserving the ordinary client defaults.
    server_verifier: ?ClientCertificateVerifier = null,
    /// Ordered TLS ALPN offers. Supplying any offer selects the vail-backed
    /// client even without a client certificate because Zig's standard TLS
    /// client does not expose ALPN configuration.
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const CipherSuite =
        &vail.tls.cipher_suite.default_preference,
    max_server_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget for the vail client handshake. The standard
    /// TLS path continues to use its own transport behavior.
    tls_handshake_timeout: ?std.Io.Duration = null,
    /// MQTT control packets are small latency-sensitive records by default.
    /// Set false to retain Nagle when batching throughput matters more.
    tcp_nodelay: bool = true,
};

/// Borrowed native-TLS target for `mqtt.reconnect.Client`. The host and all
/// TLS option slices must remain valid for the reconnect client lifetime; MQTT
/// CONNECT data is supplied separately and deeply owned by that client.
pub const ReconnectConnector = struct {
    address: net.IpAddress,
    tls_host: []const u8,
    options: ConnectOptions,

    pub fn connector(self: *ReconnectConnector) mqtt_runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        const options = reconnectOptions(self.options, mqtt_options);
        return Client.connectAddressAttempt(
            allocator,
            io,
            self.address,
            self.tls_host,
            options,
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectAddressAttemptWithDeadline(
            allocator, io, self.address, self.tls_host,
            reconnectOptions(self.options, mqtt_options), deadline,
        );
    }
};

/// Borrowed hostname target for `mqtt.reconnect.Client`. Each attempt performs
/// a fresh DNS lookup under the connector's `network_connect_timeout`; the
/// host and TLS option storage must outlive the reconnecting client.
pub const HostReconnectConnector = struct {
    host: []const u8,
    port: u16,
    options: ConnectOptions,

    pub fn connector(
        self: *HostReconnectConnector,
    ) mqtt_runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *HostReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectHostAttempt(
            allocator,
            io,
            self.host,
            self.port,
            reconnectOptions(self.options, mqtt_options),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *HostReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectHostAttemptWithDeadline(
            allocator, io, self.host, self.port,
            reconnectOptions(self.options, mqtt_options), deadline,
        );
    }
};

/// Borrowed `mqtts://`/`ssl://` target for `mqtt.reconnect.Client`. URI and
/// TLS option storage must outlive the reconnecting client. Reusing the public
/// URI attempt path keeps scheme validation, SNI, and DNS behavior identical
/// between initial connections and retries.
pub const UriReconnectConnector = struct {
    uri: []const u8,
    options: ConnectOptions,

    pub fn connector(
        self: *UriReconnectConnector,
    ) mqtt_runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *UriReconnectConnector = @ptrCast(
            @alignCast(context),
        );
        return Client.connectUriAttempt(
            allocator,
            io,
            self.uri,
            reconnectOptions(self.options, mqtt_options),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *UriReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectUriAttemptWithDeadline(
            allocator, io, self.uri,
            reconnectOptions(self.options, mqtt_options), deadline,
        );
    }
};

/// MQTT CONNECT state belongs to the reconnecting client, while the connector
/// retains network policy. In particular, copying reconnect-owned options must
/// not silently replace the timeout selected for DNS/TCP establishment.
fn reconnectOptions(
    configured: ConnectOptions,
    mqtt_options: mqtt_runtime.ConnectOptions,
) ConnectOptions {
    var options = configured;
    const network_connect_timeout = options.mqtt.network_connect_timeout;
    options.mqtt = mqtt_options;
    options.mqtt.network_connect_timeout = network_connect_timeout;
    return options;
}

fn connectStreamAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    return connectStreamAttemptMaybeBefore(
        allocator,
        io,
        stream,
        tls_host,
        options,
        null,
    );
}

fn connectStreamAttemptBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
    deadline: std.Io.Clock.Timestamp,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    _ = try deadline_policy.usableAwake(io, deadline);
    return connectStreamAttemptMaybeBefore(
        allocator,
        io,
        stream,
        tls_host,
        options,
        deadline,
    );
}

fn connectStreamAttemptMaybeBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    var stream_owned = true;
    errdefer if (stream_owned) stream.close(io);
    if (options.tcp_nodelay) {
        try socket_options.setTcpNoDelay(stream);
    }
    if (options.client_identity != null or
        options.server_verifier != null or
        options.alpn_protocols.len != 0)
    {
        // The vail helper owns teardown from this point, including handshake
        // failures before a Connection object exists.
        stream_owned = false;
        return connectVailStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            options,
            options.client_identity,
            deadline,
        );
    }
    const standard_tls_options = blk: {
        var tls_options = options.tls;
        if (tls_options.handshake_timeout == null) {
            tls_options.handshake_timeout =
                options.tls_handshake_timeout;
        }
        break :blk tls_options;
    };
    const tls_connection = if (deadline) |absolute|
        try http1_runtime.TlsClientConnection.initWithDeadline(
            allocator,
            io,
            stream,
            tls_host,
            standard_tls_options,
            absolute,
        )
    else
        try http1_runtime.TlsClientConnection.init(
            allocator,
            io,
            stream,
            tls_host,
            standard_tls_options,
        );
    stream_owned = false;

    // `initTls` is infallible and transfers ownership into the MQTT
    // connection. From this point one errdefer must own teardown; retaining a
    // second TLS errdefer would double-close on a CONNECT/CONNACK error.
    var connection = mqtt_runtime.Connection.initTls(
        allocator,
        tls_connection,
        options.mqtt,
    );
    errdefer connection.close();
    return if (deadline) |absolute|
        connection.establishClientWithDeadline(options.mqtt, absolute)
    else
        connection.establishClient(options.mqtt);
}

fn connectVailStreamAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
    client_identity: ?ClientIdentity,
    deadline: ?std.Io.Clock.Timestamp,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    var stream_owned = true;
    errdefer if (stream_owned) stream.close(io);
    const tls_options: tls_stream.ClientVerifiedOptions = .{
        .server_name = tls_host,
        .verify_host = options.tls.verify_host,
        .ca_bundle = if (options.tls.ca_bundle) |bundle|
            .{ .bundle = bundle.bundle, .lock = bundle.lock }
        else
            null,
        .server_verifier = options.server_verifier,
        .client_identity = client_identity,
        .alpn_protocols = options.alpn_protocols,
        .cipher_suites = options.cipher_suites,
        .max_server_handshake_size = options.max_server_handshake_size,
        .handshake_timeout = options.tls_handshake_timeout,
    };
    const connection = if (deadline) |absolute|
        try tls_stream.ClientConnection.initVerifiedWithDeadline(
            allocator,
            io,
            stream,
            tls_options,
            absolute,
        )
    else
        try tls_stream.ClientConnection.initVerified(
            allocator,
            io,
            stream,
            tls_options,
        );
    stream_owned = false;
    var mqtt_connection = mqtt_runtime.Connection.initVailTls(
        allocator,
        connection,
        options.mqtt,
    );
    errdefer mqtt_connection.close();
    return if (deadline) |absolute|
        mqtt_connection.establishClientWithDeadline(options.mqtt, absolute)
    else
        mqtt_connection.establishClient(options.mqtt);
}

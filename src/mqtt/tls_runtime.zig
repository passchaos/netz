const std = @import("std");
const mqtt_runtime = @import("runtime.zig");
const http1_runtime = @import("../http1/mod.zig").runtime;
const socket_options = @import("../internal/socket_options.zig");
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
                .client_auth = options.client_auth,
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
        const stream = try self.listener.accept(self.io);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        const tls_connection = try tls_stream.ServerConnection.init(
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
        return connection.accept(options);
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
    /// Request and verify a TLS 1.3 client certificate. `required` is the
    /// default within the policy; use `.optional` to retain anonymous clients.
    client_auth: ?ClientAuthPolicy = null,
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
        const stream = try host_name.connect(io, port, .{ .mode = .stream });
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            host,
            options,
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
        const stream = try address.connect(io, .{ .mode = .stream });
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            options,
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
        const uri = std.Uri.parse(uri_text) catch
            return error.InvalidUri;
        const is_mqtts =
            std.ascii.eqlIgnoreCase(uri.scheme, "mqtts") or
            std.ascii.eqlIgnoreCase(uri.scheme, "ssl");
        if (!is_mqtts) return error.UnsupportedScheme;
        var endpoint = try http1_runtime.uriEndpoint(
            allocator,
            uri,
            8883,
        );
        defer endpoint.deinit();

        const stream = try endpoint.connect(io);
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            endpoint.tls_host,
            options,
        );
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
    cipher_suites: []const CipherSuite =
        &vail.tls.cipher_suite.default_preference,
    max_server_handshake_size: usize = 256 * 1024,
    /// MQTT control packets are small latency-sensitive records by default.
    /// Set false to retain Nagle when batching throughput matters more.
    tcp_nodelay: bool = true,
};

fn connectStreamAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    var stream_owned = true;
    errdefer if (stream_owned) stream.close(io);
    if (options.tcp_nodelay) {
        try socket_options.setTcpNoDelay(stream);
    }
    if (options.client_identity) |client_identity| {
        // The vail helper owns teardown from this point, including handshake
        // failures before a Connection object exists.
        stream_owned = false;
        return connectVailStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            options,
            client_identity,
        );
    }
    const tls_connection = try http1_runtime.TlsClientConnection.init(
        allocator,
        io,
        stream,
        tls_host,
        options.tls,
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
    return connection.establishClient(options.mqtt);
}

fn connectVailStreamAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
    client_identity: ClientIdentity,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    var stream_owned = true;
    errdefer if (stream_owned) stream.close(io);
    const connection = try tls_stream.ClientConnection.initVerified(
        allocator,
        io,
        stream,
        .{
            .server_name = tls_host,
            .verify_host = options.tls.verify_host,
            .ca_bundle = if (options.tls.ca_bundle) |bundle|
                .{ .bundle = bundle.bundle, .lock = bundle.lock }
            else
                null,
            .server_verifier = options.server_verifier,
            .client_identity = client_identity,
            .cipher_suites = options.cipher_suites,
            .max_server_handshake_size = options.max_server_handshake_size,
        },
    );
    stream_owned = false;
    var mqtt_connection = mqtt_runtime.Connection.initVailTls(
        allocator,
        connection,
        options.mqtt,
    );
    errdefer mqtt_connection.close();
    return mqtt_connection.establishClient(options.mqtt);
}

const std = @import("std");
const mqtt = @import("mod.zig");
const websocket = @import("../websocket/mod.zig");
const websocket_runtime = websocket.runtime;
const http1_runtime = @import("../http1/mod.zig").runtime;
const packet_transport = @import("runtime/packet_transport.zig");
const tls_stream = @import("../tls/mod.zig").stream;

const net = std.Io.net;

pub const Error = packet_transport.Error || error{
    PacketTooLarge,
    UnexpectedPacket,
    ConnectRefused,
    InflightFull,
    ReceiveMaximumExceeded,
    OutgoingPacketTooLarge,
    PublishRefused,
    SubscriptionRefused,
} || websocket_runtime.Error || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.Thread.SpawnError;

pub const Limits = struct {
    max_packet_size: usize = 16 * 1024 * 1024,
};

const packet_identifier_slots = @as(usize, std.math.maxInt(u16)) + 1;
const topic_alias_slots: usize = 16;

const PacketTransport = packet_transport.Transport;

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: net.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try bind_address.listen(io, .{ .reuse_address = true }),
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
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);

        var connection = Connection{
            .allocator = self.allocator,
            .transport = .initTcp(self.io, stream),
            .protocol = options.protocol,
            .limits = self.limits,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .incoming_topic_alias_maximum = effectiveTopicAliasMaximum(options.topic_alias_maximum),
        };
        errdefer connection.close();
        return connection.accept(options);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *AcceptedClient) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(?anyerror, max_connections);
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var accepted = try self.accept(options);
            errdefer accepted.deinit(self.allocator);
            const task = ServeTask(HandlerContext){
                .accepted = accepted,
                .context = context,
                .handler = handler,
                .result = result,
                .allocator = self.allocator,
            };
            group.async(self.io, ServeTask(HandlerContext).run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .errors = results };
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
    session_present: bool = false,
    reason_code: u8 = 0,
    max_outgoing_inflight: u16 = 16,
    topic_alias_maximum: u16 = 16,
    server_keep_alive_seconds: ?u16 = null,
    maximum_qos: ?mqtt.QoS = null,
    retain_available: bool = true,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
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

pub const Client = struct {
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

    pub fn connectAttempt(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, options: ConnectOptions) Error!ConnectAttempt {
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        var connection = Connection{
            .allocator = allocator,
            .transport = .initTcp(io, stream),
            .protocol = options.protocol,
            .limits = options.limits,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .max_incoming_inflight = mqtt.receiveMaximum(options.properties) orelse options.max_outgoing_inflight,
            .incoming_topic_alias_maximum = effectiveTopicAliasMaximum(options.topic_alias_maximum),
            .peer_maximum_qos = options.peer_maximum_qos,
            .peer_retain_available = options.peer_retain_available,
        };
        errdefer connection.close();

        return connection.establishClient(options);
    }
};

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
    max_outgoing_inflight: u16 = 16,
    topic_alias_maximum: u16 = 16,
};

fn applyConnAckNegotiation(
    connection: *Connection,
    connack: mqtt.ConnAck,
) void {
    if (mqtt.receiveMaximum(connack.properties)) |receive_maximum| {
        connection.max_outgoing_inflight = negotiatedOutgoingInflightLimit(
            connection.max_outgoing_inflight,
            receive_maximum,
        );
    }
    if (mqtt.maximumPacketSize(connack.properties)) |maximum_packet_size| {
        connection.peer_max_packet_size = maximum_packet_size;
    }
    if (mqtt.topicAliasMaximum(connack.properties)) |topic_alias_maximum| {
        connection.peer_topic_alias_maximum = topic_alias_maximum;
    }
    if (mqtt.serverKeepAlive(connack.properties)) |server_keep_alive| {
        connection.keep_alive_seconds = server_keep_alive;
    }
    if (mqtt.maximumQoS(connack.properties)) |maximum_qos| {
        connection.peer_maximum_qos = maximum_qos;
    }
    if (mqtt.retainAvailable(connack.properties)) |retain_available| {
        connection.peer_retain_available = retain_available;
    }
    if (mqtt.wildcardSubscriptionAvailable(connack.properties)) |available| {
        connection.peer_wildcard_subscription_available = available;
    }
    if (mqtt.subscriptionIdentifierAvailable(connack.properties)) |available| {
        connection.peer_subscription_identifier_available = available;
    }
    if (mqtt.sharedSubscriptionAvailable(connack.properties)) |available| {
        connection.peer_shared_subscription_available = available;
    }
}

pub const ConnAckOptions = struct {
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

fn effectiveTopicAliasMaximum(configured: u16) u16 {
    return @min(configured, @as(u16, @intCast(topic_alias_slots)));
}

fn negotiatedOutgoingInflightLimit(local_upper_limit: u16, peer_receive_maximum: u16) u16 {
    // MQTT 5 Receive Maximum is the peer's limit for QoS 1/2 PUBLISH packets
    // that we may have in flight.  Like rumqtt, keep the configured local
    // upper bound as a hard ceiling so a peer cannot enlarge local queue/window
    // state by advertising a larger value in CONNECT/CONNACK.
    return @min(local_upper_limit, peer_receive_maximum);
}

fn validateTopicAliasMaximumFitsRuntime(properties: []const mqtt.Property) Error!void {
    if (mqtt.topicAliasMaximum(properties)) |maximum| {
        if (maximum > @as(u16, @intCast(topic_alias_slots))) return error.InvalidProperty;
    }
}

fn appendTopicAliasMaximumSetting(
    properties: *std.ArrayList(mqtt.Property),
    allocator: std.mem.Allocator,
    explicit_properties: []const mqtt.Property,
    configured_maximum: u16,
) Error!void {
    try validateTopicAliasMaximumFitsRuntime(explicit_properties);
    if (mqtt.topicAliasMaximum(explicit_properties) == null) {
        try properties.append(allocator, .{
            .two_byte = .{
                .id = .topic_alias_maximum,
                .value = effectiveTopicAliasMaximum(configured_maximum),
            },
        });
    }
}

pub const Connection = struct {
    allocator: std.mem.Allocator,
    transport: PacketTransport,
    protocol: mqtt.ProtocolVersion = .v5,
    limits: Limits = .{},
    next_packet_id: u16 = 1,
    outgoing_inflight: u16 = 0,
    max_outgoing_inflight: u16 = 16,
    incoming_inflight: u16 = 0,
    max_incoming_inflight: u16 = 16,
    peer_max_packet_size: usize = std.math.maxInt(usize),
    incoming_topic_alias_maximum: u16 = 16,
    peer_topic_alias_maximum: u16 = 0,
    keep_alive_seconds: u16 = 30,
    peer_maximum_qos: mqtt.QoS = .exactly_once,
    local_maximum_qos: mqtt.QoS = .exactly_once,
    peer_retain_available: bool = true,
    local_retain_available: bool = true,
    peer_wildcard_subscription_available: bool = true,
    peer_subscription_identifier_available: bool = true,
    peer_shared_subscription_available: bool = true,
    local_wildcard_subscription_available: bool = true,
    local_subscription_identifier_available: bool = true,
    local_shared_subscription_available: bool = true,
    incoming_qos1: std.StaticBitSet(packet_identifier_slots) = .empty,
    incoming_qos2: std.StaticBitSet(packet_identifier_slots) = .empty,
    outgoing_qos1: std.StaticBitSet(packet_identifier_slots) = .empty,
    outgoing_qos2: std.StaticBitSet(packet_identifier_slots) = .empty,
    outgoing_qos2_pubrel: std.StaticBitSet(packet_identifier_slots) = .empty,
    incoming_topic_aliases: [topic_alias_slots]?[]u8 = [_]?[]u8{null} ** topic_alias_slots,
    outgoing_topic_aliases: [topic_alias_slots]?[]u8 = [_]?[]u8{null} ** topic_alias_slots,

    /// Wrap an already-negotiated WebSocket connection in the shared MQTT
    /// session state. Prefer `mqtt.websocket_runtime.Client`/`Server` unless
    /// the caller owns the WebSocket opening handshake.
    pub fn initWebSocket(
        allocator: std.mem.Allocator,
        ws: websocket_runtime.Connection,
        protocol: mqtt.ProtocolVersion,
        limits: Limits,
        max_outgoing_inflight: u16,
        topic_alias_maximum: u16,
    ) Connection {
        return .{
            .allocator = allocator,
            .transport = .initWebSocket(ws),
            .protocol = protocol,
            .limits = limits,
            .max_outgoing_inflight = max_outgoing_inflight,
            .incoming_topic_alias_maximum = effectiveTopicAliasMaximum(
                topic_alias_maximum,
            ),
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
            .limits = options.limits,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .max_incoming_inflight = mqtt.receiveMaximum(options.properties) orelse
                options.max_outgoing_inflight,
            .incoming_topic_alias_maximum = effectiveTopicAliasMaximum(
                options.topic_alias_maximum,
            ),
            .peer_maximum_qos = options.peer_maximum_qos,
            .peer_retain_available = options.peer_retain_available,
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
            .limits = limits,
            .max_outgoing_inflight = max_outgoing_inflight,
            .incoming_topic_alias_maximum = effectiveTopicAliasMaximum(
                topic_alias_maximum,
            ),
        };
    }

    pub fn close(self: *Connection) void {
        for (self.incoming_topic_aliases) |maybe_topic| {
            if (maybe_topic) |topic| self.allocator.free(topic);
        }
        for (self.outgoing_topic_aliases) |maybe_topic| {
            if (maybe_topic) |topic| self.allocator.free(topic);
        }
        self.transport.close(self.allocator);
        self.* = undefined;
    }

    /// Return the verified client certificate chain for an mTLS server
    /// connection. The DER slices are owned by the transport and remain valid
    /// until `close`; anonymous or non-mTLS transports return null.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        return self.transport.peerCertificates();
    }

    /// Complete the broker side of MQTT CONNECT on an already-open transport.
    ///
    /// Transport adapters call this after their own opening handshake, which
    /// keeps all MQTT capability and inflight negotiation in one state machine.
    pub fn accept(
        self: *Connection,
        options: AcceptOptions,
    ) Error!AcceptedClient {
        var connect = try self.readConnect();
        errdefer connect.deinit(self.allocator);
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
        try self.writeConnAck(.{
            .session_present = options.session_present,
            .reason_code = options.reason_code,
            .max_outgoing_inflight = options.max_outgoing_inflight,
            .topic_alias_maximum = options.topic_alias_maximum,
            .server_keep_alive_seconds = options.server_keep_alive_seconds,
            .maximum_qos = options.maximum_qos,
            .retain_available = options.retain_available,
            .wildcard_subscription_available = options.wildcard_subscription_available,
            .subscription_identifier_available = options.subscription_identifier_available,
            .shared_subscription_available = options.shared_subscription_available,
        });

        const owned_connection = self.*;
        self.* = undefined;
        return .{
            .connection = owned_connection,
            .connect = connect,
        };
    }

    /// Send CONNECT and process CONNACK on an already-open transport.
    pub fn establishClient(
        self: *Connection,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        // This method transfers `self` into the returned attempt. Capture the
        // allocator before that move so deferred temporary cleanup never reads
        // the deliberately undefined moved-from connection.
        const allocator = self.allocator;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        var connect_properties: std.ArrayList(mqtt.Property) = .empty;
        defer connect_properties.deinit(allocator);
        try connect_properties.appendSlice(
            allocator,
            options.properties,
        );
        if (options.protocol == .v5 and
            mqtt.receiveMaximum(options.properties) == null)
        {
            try connect_properties.append(
                allocator,
                .{ .two_byte = .{
                    .id = .receive_maximum,
                    .value = options.max_outgoing_inflight,
                } },
            );
        }
        if (options.protocol == .v5 and
            mqtt.maximumPacketSize(options.properties) == null and
            options.limits.max_packet_size <= std.math.maxInt(u32))
        {
            try connect_properties.append(
                allocator,
                .{ .four_byte = .{
                    .id = .maximum_packet_size,
                    .value = @intCast(options.limits.max_packet_size),
                } },
            );
        }
        if (options.protocol == .v5) {
            try appendTopicAliasMaximumSetting(
                &connect_properties,
                allocator,
                options.properties,
                options.topic_alias_maximum,
            );
            self.max_incoming_inflight =
                mqtt.receiveMaximum(connect_properties.items) orelse
                self.max_incoming_inflight;
            self.incoming_topic_alias_maximum =
                mqtt.topicAliasMaximum(connect_properties.items) orelse
                self.incoming_topic_alias_maximum;
        }
        try mqtt.writeConnectPacket(
            &encoded,
            allocator,
            options.protocol,
            .{
                .client_id = options.client_id,
                .clean_start = options.clean_start,
                .keep_alive_seconds = options.keep_alive_seconds,
                .properties = connect_properties.items,
                .will = options.will,
                .username = options.username,
                .password = options.password,
            },
        );
        try self.writePacket(encoded.items);

        var connack = try self.readConnAck();
        errdefer connack.deinit(allocator);
        if (connack.connack.reason_code != 0) {
            self.close();
            return .{ .connection = null, .connack = connack };
        }
        applyConnAckNegotiation(self, connack.connack);

        const owned_connection = self.*;
        self.* = undefined;
        return .{ .connection = owned_connection, .connack = connack };
    }

    pub fn readConnect(self: *Connection) Error!OwnedConnect {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .connect) return error.UnexpectedPacket;
        var connect = try mqtt.Connect.parse(self.allocator, packet.bytes);
        errdefer connect.deinit(self.allocator);
        self.protocol = connect.protocol;
        self.keep_alive_seconds = connect.keep_alive_seconds;
        return .{ .packet = packet, .connect = connect };
    }

    pub fn writeConnAck(self: *Connection, options: ConnAckOptions) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.appendSlice(self.allocator, options.properties);
        if (self.protocol == .v5 and mqtt.receiveMaximum(options.properties) == null) {
            try properties.append(self.allocator, .{ .two_byte = .{ .id = .receive_maximum, .value = options.max_outgoing_inflight } });
        }
        if (self.protocol == .v5 and mqtt.maximumPacketSize(options.properties) == null and self.limits.max_packet_size <= std.math.maxInt(u32)) {
            try properties.append(self.allocator, .{ .four_byte = .{ .id = .maximum_packet_size, .value = @intCast(self.limits.max_packet_size) } });
        }
        if (self.protocol == .v5) {
            try appendTopicAliasMaximumSetting(&properties, self.allocator, options.properties, options.topic_alias_maximum);
        }
        if (self.protocol == .v5 and mqtt.serverKeepAlive(options.properties) == null) {
            if (options.server_keep_alive_seconds) |keep_alive| {
                try properties.append(self.allocator, .{ .two_byte = .{ .id = .server_keep_alive, .value = keep_alive } });
            }
        }
        if (self.protocol == .v5 and mqtt.maximumQoS(options.properties) == null) {
            if (options.maximum_qos) |maximum_qos| {
                // MQTT 5 Maximum QoS can only advertise a restriction to QoS 0
                // or QoS 1.  QoS 2 support is the default, so do not encode the
                // property when the configured maximum is exactly_once.
                if (maximum_qos != .exactly_once) {
                    try properties.append(self.allocator, .{ .byte = .{ .id = .maximum_qos, .value = @intFromEnum(maximum_qos) } });
                }
            }
        }
        if (self.protocol == .v5 and mqtt.retainAvailable(options.properties) == null and !options.retain_available) {
            try properties.append(self.allocator, .{ .byte = .{ .id = .retain_available, .value = 0 } });
        }
        if (self.protocol == .v5 and mqtt.wildcardSubscriptionAvailable(options.properties) == null and !options.wildcard_subscription_available) {
            try properties.append(self.allocator, .{ .byte = .{ .id = .wildcard_subscription_available, .value = 0 } });
        }
        if (self.protocol == .v5 and mqtt.subscriptionIdentifierAvailable(options.properties) == null and !options.subscription_identifier_available) {
            try properties.append(self.allocator, .{ .byte = .{ .id = .subscription_identifier_available, .value = 0 } });
        }
        if (self.protocol == .v5 and mqtt.sharedSubscriptionAvailable(options.properties) == null and !options.shared_subscription_available) {
            try properties.append(self.allocator, .{ .byte = .{ .id = .shared_subscription_available, .value = 0 } });
        }
        try mqtt.ConnAck.write(&encoded, self.allocator, self.protocol, options.session_present, options.reason_code, properties.items);
        try self.writePacket(encoded.items);
        if (self.protocol == .v5) {
            self.max_incoming_inflight = mqtt.receiveMaximum(properties.items) orelse self.max_incoming_inflight;
            self.incoming_topic_alias_maximum = mqtt.topicAliasMaximum(properties.items) orelse self.incoming_topic_alias_maximum;
            self.local_maximum_qos = mqtt.maximumQoS(properties.items) orelse options.maximum_qos orelse .exactly_once;
            self.local_retain_available = mqtt.retainAvailable(properties.items) orelse options.retain_available;
            self.local_wildcard_subscription_available = mqtt.wildcardSubscriptionAvailable(properties.items) orelse options.wildcard_subscription_available;
            self.local_subscription_identifier_available = mqtt.subscriptionIdentifierAvailable(properties.items) orelse options.subscription_identifier_available;
            self.local_shared_subscription_available = mqtt.sharedSubscriptionAvailable(properties.items) orelse options.shared_subscription_available;
        }
    }

    pub fn readConnAck(self: *Connection) Error!OwnedConnAck {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .connack) return error.UnexpectedPacket;
        var connack = try mqtt.ConnAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer connack.deinit(self.allocator);
        return .{ .packet = packet, .connack = connack };
    }

    pub fn publish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!void {
        const packet_id = try self.writePublish(topic, payload, options);
        if (packet_id) |id| try self.completePublish(id, options.qos);
    }

    pub fn writePublish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!?u16 {
        if (@intFromEnum(options.qos) > @intFromEnum(self.peer_maximum_qos)) return error.InvalidQoS;
        if (options.retain and !self.peer_retain_available) return error.InvalidProperty;
        try self.validateOutgoingTopicAlias(topic, options.properties);

        const packet_id = if (options.qos == .at_most_once) null else try self.reserveOutgoingPublish(options.qos);
        errdefer if (packet_id) |id| self.releaseOutgoingPublish(id, options.qos);

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.writePublish(&encoded, self.allocator, self.protocol, topic, payload, .{
            .qos = options.qos,
            .retain = options.retain,
            .dup = options.dup,
            .packet_id = packet_id,
            .properties = options.properties,
        });
        try self.writePacket(encoded.items);
        try self.rememberOutgoingTopicAlias(topic, options.properties);
        return packet_id;
    }

    pub fn completePublish(self: *Connection, packet_id: u16, qos: mqtt.QoS) Error!void {
        switch (qos) {
            .at_most_once => return,
            .at_least_once => try self.completePublishPubAck(packet_id),
            .exactly_once => try self.completePublishQoS2(packet_id),
        }
    }

    pub fn completePublishPubAck(self: *Connection, packet_id: u16) Error!void {
        if (packet_id != 0 and !self.outgoing_qos1.isSet(@as(usize, packet_id))) return error.UnexpectedPacket;
        var ack = try self.readPubAck();
        defer ack.deinit(self.allocator);
        if (packet_id != 0 and ack.ack.packet_id != packet_id) return error.UnexpectedPacket;
        if (!self.outgoing_qos1.isSet(@as(usize, ack.ack.packet_id))) return error.UnexpectedPacket;
        self.releaseOutgoingPublish(ack.ack.packet_id, .at_least_once);
        if (!ack.ack.accepted()) return error.PublishRefused;
    }

    pub fn completePublishQoS2(self: *Connection, packet_id: u16) Error!void {
        const id = try self.completePublishPubRec(packet_id);
        try self.completePublishPubComp(id);
    }

    pub fn completePublishPubRec(self: *Connection, packet_id: u16) Error!u16 {
        if (packet_id != 0 and !self.outgoing_qos2.isSet(@as(usize, packet_id))) return error.UnexpectedPacket;
        var pubrec = try self.readPubRec();
        defer pubrec.deinit(self.allocator);
        if (packet_id != 0 and pubrec.ack.packet_id != packet_id) return error.UnexpectedPacket;
        if (!self.outgoing_qos2.isSet(@as(usize, pubrec.ack.packet_id))) return error.UnexpectedPacket;
        if (!pubrec.ack.accepted()) {
            self.releaseOutgoingPublish(pubrec.ack.packet_id, .exactly_once);
            return error.PublishRefused;
        }
        try self.writePubRel(pubrec.ack.packet_id, 0);
        self.outgoing_qos2.setValue(@as(usize, pubrec.ack.packet_id), false);
        self.outgoing_qos2_pubrel.set(@as(usize, pubrec.ack.packet_id));
        return pubrec.ack.packet_id;
    }

    pub fn completePublishPubComp(self: *Connection, packet_id: u16) Error!void {
        if (!self.outgoing_qos2_pubrel.isSet(@as(usize, packet_id))) return error.UnexpectedPacket;
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
        var publish_packet = try mqtt.Publish.parse(self.allocator, self.protocol, packet.bytes);
        errdefer publish_packet.deinit(self.allocator);
        try self.validateIncomingPublishCapabilities(publish_packet);
        try self.applyIncomingTopicAlias(&publish_packet);
        try self.recordIncomingPublish(publish_packet);
        return .{ .packet = packet, .publish = publish_packet };
    }

    pub fn writePubAck(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.puback, packet_id, reason_code, &.{});
        self.completeIncomingPublish(.puback, packet_id);
    }

    pub fn readPubAck(self: *Connection) Error!OwnedAck {
        return self.readAck(.puback);
    }

    pub fn writePubRec(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.pubrec, packet_id, reason_code, &.{});
        self.completeIncomingPubRec(packet_id, reason_code);
    }

    pub fn readPubRec(self: *Connection) Error!OwnedAck {
        return self.readAck(.pubrec);
    }

    pub fn writePubRel(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.pubrel, packet_id, reason_code, &.{});
    }

    pub fn readPubRel(self: *Connection) Error!OwnedAck {
        var pubrel = try self.readAck(.pubrel);
        errdefer pubrel.deinit(self.allocator);
        try self.validateIncomingPubRel(pubrel.ack.packet_id);
        return pubrel;
    }

    pub fn writePubComp(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacket(.pubcomp, packet_id, reason_code, &.{});
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

    fn writeAckPacket(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16, reason_code: u8, properties: []const mqtt.Property) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.AckPacket.write(&encoded, self.allocator, self.protocol, packet_type, packet_id, reason_code, properties);
        try self.writePacket(encoded.items);
    }

    pub fn subscribe(self: *Connection, subscriptions: []const mqtt.Subscription, options: SubscribeOptions) Error!OwnedSubAck {
        try self.validateOutgoingSubscribe(subscriptions, options.properties);
        const packet_id = self.nextPacketId();
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.Subscribe.write(&encoded, self.allocator, self.protocol, packet_id, options.properties, subscriptions);
        try self.writePacket(encoded.items);

        var suback = try self.readSubAck();
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
        try self.validateIncomingSubscribe(subscribe_packet.subscriptions, subscribe_packet.properties);
        return .{ .packet = packet, .subscribe = subscribe_packet };
    }

    pub fn writeSubAck(self: *Connection, packet_id: u16, reason_codes: []const u8, properties: []const mqtt.Property) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.SubAck.write(&encoded, self.allocator, self.protocol, packet_id, properties, reason_codes);
        try self.writePacket(encoded.items);
    }

    pub fn readSubAck(self: *Connection) Error!OwnedSubAck {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .suback) return error.UnexpectedPacket;
        var suback = try mqtt.SubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer suback.deinit(self.allocator);
        return .{ .packet = packet, .suback = suback };
    }

    pub fn unsubscribe(self: *Connection, topic_filters: []const []const u8, options: UnsubscribeOptions) Error!OwnedUnsubAck {
        const packet_id = self.nextPacketId();
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.Unsubscribe.write(&encoded, self.allocator, self.protocol, packet_id, options.properties, topic_filters);
        try self.writePacket(encoded.items);

        var unsuback = try self.readUnsubAck();
        errdefer unsuback.deinit(self.allocator);
        try validateUnsubAckResponse(self.protocol, unsuback.unsuback, packet_id, topic_filters.len);
        return unsuback;
    }

    pub fn readUnsubscribe(self: *Connection) Error!OwnedUnsubscribe {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .unsubscribe) return error.UnexpectedPacket;
        var unsubscribe_packet = try mqtt.Unsubscribe.parse(self.allocator, self.protocol, packet.bytes);
        errdefer unsubscribe_packet.deinit(self.allocator);
        return .{ .packet = packet, .unsubscribe = unsubscribe_packet };
    }

    pub fn writeUnsubAck(self: *Connection, packet_id: u16, reason_codes: []const u8, properties: []const mqtt.Property) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.UnsubAck.write(&encoded, self.allocator, self.protocol, packet_id, properties, reason_codes);
        try self.writePacket(encoded.items);
    }

    pub fn readUnsubAck(self: *Connection) Error!OwnedUnsubAck {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .unsuback) return error.UnexpectedPacket;
        var unsuback = try mqtt.UnsubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer unsuback.deinit(self.allocator);
        return .{ .packet = packet, .unsuback = unsuback };
    }

    pub fn ping(self: *Connection) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.writePing(&encoded, self.allocator, false);
        try self.writePacket(encoded.items);
        var packet = try self.readPacket();
        defer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .pingresp) return error.UnexpectedPacket;
        try mqtt.validatePing(packet.bytes, true);
    }

    pub fn readPingReq(self: *Connection) Error!void {
        var packet = try self.readPacket();
        defer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .pingreq) return error.UnexpectedPacket;
        try mqtt.validatePing(packet.bytes, false);
    }

    pub fn writePingResp(self: *Connection) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.writePing(&encoded, self.allocator, true);
        try self.writePacket(encoded.items);
    }

    pub fn disconnect(self: *Connection, reason_code: u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.Disconnect.write(&encoded, self.allocator, self.protocol, reason_code, &.{});
        try self.writePacket(encoded.items);
    }

    pub fn readDisconnect(self: *Connection) Error!OwnedDisconnect {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .disconnect) return error.UnexpectedPacket;
        var disconnect_packet = try mqtt.Disconnect.parse(self.allocator, self.protocol, packet.bytes);
        errdefer disconnect_packet.deinit(self.allocator);
        return .{ .packet = packet, .disconnect = disconnect_packet };
    }

    pub fn writeAuth(self: *Connection, reason_code: u8, properties: []const mqtt.Property) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try mqtt.Auth.write(&encoded, self.allocator, self.protocol, reason_code, properties);
        try self.writePacket(encoded.items);
    }

    pub fn readAuth(self: *Connection) Error!OwnedAuth {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != .auth) return error.UnexpectedPacket;
        var auth_packet = try mqtt.Auth.parse(self.allocator, self.protocol, packet.bytes);
        errdefer auth_packet.deinit(self.allocator);
        return .{ .packet = packet, .auth = auth_packet };
    }

    fn validateOutgoingTopicAlias(self: *Connection, topic: []const u8, properties: []const mqtt.Property) Error!void {
        const alias = mqtt.topicAlias(properties) orelse return;
        if (alias == 0 or alias > self.peer_topic_alias_maximum or alias > self.outgoing_topic_aliases.len) return error.InvalidProperty;
        if (topic.len == 0 and self.outgoing_topic_aliases[alias - 1] == null) return error.InvalidTopic;
    }

    fn rememberOutgoingTopicAlias(self: *Connection, topic: []const u8, properties: []const mqtt.Property) Error!void {
        const alias = mqtt.topicAlias(properties) orelse return;
        if (topic.len == 0) return;
        const index = alias - 1;
        if (self.outgoing_topic_aliases[index]) |old| self.allocator.free(old);
        self.outgoing_topic_aliases[index] = try self.allocator.dupe(u8, topic);
    }

    fn applyIncomingTopicAlias(self: *Connection, publish_packet: *mqtt.Publish) Error!void {
        const alias = mqtt.topicAlias(publish_packet.properties) orelse {
            try mqtt.validateTopicName(publish_packet.topic);
            return;
        };
        if (alias == 0 or alias > self.incoming_topic_alias_maximum or alias > self.incoming_topic_aliases.len) return error.InvalidProperty;
        const index = alias - 1;
        if (publish_packet.topic.len != 0) {
            try mqtt.validateTopicName(publish_packet.topic);
            if (self.incoming_topic_aliases[index]) |old| self.allocator.free(old);
            self.incoming_topic_aliases[index] = try self.allocator.dupe(u8, publish_packet.topic);
            return;
        }
        const stored = self.incoming_topic_aliases[index] orelse return error.InvalidTopic;
        publish_packet.topic = stored;
    }

    fn validateIncomingPublishCapabilities(self: Connection, publish_packet: mqtt.Publish) Error!void {
        if (@intFromEnum(publish_packet.qos) > @intFromEnum(self.local_maximum_qos)) return error.InvalidQoS;
        if (publish_packet.retain and !self.local_retain_available) return error.InvalidProperty;
    }

    fn validateIncomingPubRel(self: Connection, packet_id: u16) Error!void {
        // A PUBREL is valid only after this endpoint has received a QoS 2
        // PUBLISH with the same Packet Identifier and answered PUBREC.  Rumqtt
        // treats an unsolicited PUBREL as a state error; preserve that guard so
        // peer bugs cannot complete or disturb unrelated QoS state.
        if (!self.incoming_qos2.isSet(@as(usize, packet_id))) return error.InvalidPacketIdentifier;
    }

    fn recordIncomingPublish(self: *Connection, publish_packet: mqtt.Publish) Error!void {
        const packet_id = publish_packet.packet_id orelse return;
        const index = @as(usize, packet_id);
        const set = switch (publish_packet.qos) {
            .at_most_once => return,
            .at_least_once => &self.incoming_qos1,
            .exactly_once => &self.incoming_qos2,
        };
        const other_set = switch (publish_packet.qos) {
            .at_most_once => unreachable,
            .at_least_once => &self.incoming_qos2,
            .exactly_once => &self.incoming_qos1,
        };

        if (other_set.isSet(index)) return error.InvalidPacketIdentifier;
        // Retransmissions reuse the same Packet Identifier and must not consume
        // another Receive Maximum slot.  This mirrors rumqtt's fixed-bitset
        // state tables: Packet Identifier is the stable O(1) lookup key, so a
        // retry cannot grow memory or make the connection look over quota.
        if (set.isSet(index)) return;
        if (self.incoming_inflight >= self.max_incoming_inflight) return error.ReceiveMaximumExceeded;
        set.set(index);
        self.incoming_inflight += 1;
    }

    fn completeIncomingPublish(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16) void {
        const set = switch (packet_type) {
            .puback => &self.incoming_qos1,
            .pubcomp => &self.incoming_qos2,
            else => return,
        };
        const index = @as(usize, packet_id);
        if (!set.isSet(index)) return;
        set.setValue(index, false);
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
        try validateSubscribeCapabilities(
            subscriptions,
            properties,
            self.peer_wildcard_subscription_available,
            self.peer_subscription_identifier_available,
            self.peer_shared_subscription_available,
        );
    }

    fn validateIncomingSubscribe(self: Connection, subscriptions: []const mqtt.Subscription, properties: []const mqtt.Property) Error!void {
        try validateSubscribeCapabilities(
            subscriptions,
            properties,
            self.local_wildcard_subscription_available,
            self.local_subscription_identifier_available,
            self.local_shared_subscription_available,
        );
    }

    fn validateSubscribeCapabilities(
        subscriptions: []const mqtt.Subscription,
        properties: []const mqtt.Property,
        wildcard_available: bool,
        subscription_identifier_available: bool,
        shared_available: bool,
    ) Error!void {
        if (!subscription_identifier_available and mqtt.subscriptionIdentifier(properties) != null) return error.SubscriptionRefused;
        for (subscriptions) |subscription| {
            if (!wildcard_available and mqtt.hasWildcards(subscription.topic_filter)) return error.SubscriptionRefused;
            if (!shared_available and std.mem.startsWith(u8, subscription.topic_filter, "$share/")) return error.SubscriptionRefused;
        }
    }

    fn writePacket(self: *Connection, bytes: []u8) Error!void {
        if (bytes.len > self.peer_max_packet_size) return error.OutgoingPacketTooLarge;
        try self.transport.writePacket(bytes);
    }

    fn readPacket(self: *Connection) Error!OwnedPacket {
        const packet = try self.transport.readPacket(
            self.allocator,
            self.limits.max_packet_size,
        );
        return .{
            .bytes = packet.bytes,
            .fixed = packet.fixed,
        };
    }

    fn readAck(self: *Connection, packet_type: mqtt.PacketType) Error!OwnedAck {
        var packet = try self.readPacket();
        errdefer packet.deinit(self.allocator);
        if (packet.fixed.packet_type != packet_type) return error.UnexpectedPacket;
        var ack = try mqtt.AckPacket.parse(self.allocator, self.protocol, packet.bytes);
        errdefer ack.deinit(self.allocator);
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

        var attempts: usize = 0;
        while (attempts < std.math.maxInt(u16)) : (attempts += 1) {
            const packet_id = self.nextPacketId();
            const index = @as(usize, packet_id);
            if (self.outgoing_qos1.isSet(index) or self.outgoing_qos2.isSet(index) or self.outgoing_qos2_pubrel.isSet(index)) continue;

            switch (qos) {
                .at_most_once => unreachable,
                .at_least_once => self.outgoing_qos1.set(index),
                .exactly_once => self.outgoing_qos2.set(index),
            }
            self.outgoing_inflight += 1;
            return packet_id;
        }
        return error.InflightFull;
    }

    fn releaseOutgoingPublish(self: *Connection, packet_id: u16, qos: mqtt.QoS) void {
        const index = @as(usize, packet_id);
        const set = switch (qos) {
            .at_most_once => return,
            .at_least_once => &self.outgoing_qos1,
            .exactly_once => &self.outgoing_qos2,
        };
        if (qos == .exactly_once and self.outgoing_qos2_pubrel.isSet(index)) {
            self.outgoing_qos2_pubrel.setValue(index, false);
        } else if (set.isSet(index)) {
            set.setValue(index, false);
        } else return;
        self.outgoing_inflight -= 1;
    }
};

fn validateUnsubAckResponse(protocol: mqtt.ProtocolVersion, unsuback: mqtt.UnsubAck, packet_id: u16, topic_filter_count: usize) Error!void {
    if (unsuback.packet_id != packet_id) return error.UnexpectedPacket;
    switch (protocol) {
        .v5 => if (unsuback.reason_codes.len != topic_filter_count) return error.UnexpectedPacket,
        // MQTT 3.1.1 UNSUBACK acknowledges only the Packet Identifier.  Unlike
        // MQTT 5, it has no per-topic reason-code vector, so a single v3
        // UNSUBACK can validly confirm an UNSUBSCRIBE that contained multiple
        // topic filters.  Keep this aligned with rumqtt's v4 UnsubAck model.
        .v3_1_1 => {},
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

pub const OwnedPacket = struct {
    bytes: []u8,
    fixed: mqtt.FixedHeader,

    pub fn deinit(self: *OwnedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedConnect = struct {
    packet: OwnedPacket,
    connect: mqtt.Connect,

    pub fn deinit(self: *OwnedConnect, allocator: std.mem.Allocator) void {
        self.connect.deinit(allocator);
        self.packet.deinit(allocator);
        self.* = undefined;
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
                .topic_alias_maximum = 4,
                .server_keep_alive_seconds = 7,
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
            try std.testing.expectEqual(@as(?u16, 3), mqtt.receiveMaximum(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(?u32, 4096), mqtt.maximumPacketSize(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(?u16, 4), mqtt.topicAliasMaximum(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(u16, 2), accepted.connection.max_outgoing_inflight);
            try std.testing.expectEqual(@as(usize, 4096), accepted.connection.peer_max_packet_size);
            try std.testing.expectEqual(@as(u16, 30), accepted.connection.keep_alive_seconds);

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
            try accepted.connection.writeUnsubAck(unsubscribe.unsubscribe.packet_id, &unsub_reasons, &.{});

            try accepted.connection.publish("alerts/system", "online", .{});

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
        .max_outgoing_inflight = 3,
        .topic_alias_maximum = 4,
    });
    defer client.close();
    try std.testing.expectEqual(@as(u16, 2), client.max_outgoing_inflight);
    try std.testing.expectEqual(@as(usize, 4096), client.peer_max_packet_size);
    try std.testing.expectEqual(@as(u16, 4), client.peer_topic_alias_maximum);
    try std.testing.expectEqual(@as(u16, 7), client.keep_alive_seconds);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, client.peer_maximum_qos);
    try std.testing.expect(!client.peer_retain_available);

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
    try std.testing.expect(!client.outgoing_qos1.isSet(@as(usize, second_id)));
    try std.testing.expect(client.outgoing_qos1.isSet(@as(usize, first_id)));
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
    try std.testing.expect(!client.outgoing_qos2.isSet(@as(usize, second_id)));
    try std.testing.expect(client.outgoing_qos2_pubrel.isSet(@as(usize, second_id)));
    try std.testing.expect(client.outgoing_qos2.isSet(@as(usize, first_id)));
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    const first_rec = try client.completePublishPubRec(0);
    try std.testing.expectEqual(first_id, first_rec);
    try std.testing.expect(client.outgoing_qos2_pubrel.isSet(@as(usize, first_id)));
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

    try std.testing.expectError(error.OutgoingPacketTooLarge, connection.publish("limited/topic", "payload too large", .{}));
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

test "MQTT connection enforces incoming receive maximum" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .max_incoming_inflight = 1,
    };

    const first = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/one",
        .packet_id = 10,
        .payload = "first",
    };
    try connection.recordIncomingPublish(first);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    var retry = first;
    retry.dup = true;
    try connection.recordIncomingPublish(retry);
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
    try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/two",
        .packet_id = 11,
        .payload = "second",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
}

test "MQTT connection keeps QoS2 receive slot until PUBCOMP" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .max_incoming_inflight = 1,
    };

    try connection.recordIncomingPublish(.{
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
    try connection.recordIncomingPublish(.{
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
        .peer_wildcard_subscription_available = false,
        .peer_subscription_identifier_available = false,
        .peer_shared_subscription_available = false,
    };

    try connection.validateOutgoingSubscribe(&exact, &.{});
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&wildcard, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&shared, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&exact, &sub_id));

    connection.local_wildcard_subscription_available = false;
    connection.local_subscription_identifier_available = false;
    connection.local_shared_subscription_available = false;
    try connection.validateIncomingSubscribe(&exact, &.{});
    try std.testing.expectError(error.SubscriptionRefused, connection.validateIncomingSubscribe(&wildcard, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateIncomingSubscribe(&shared, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateIncomingSubscribe(&exact, &sub_id));
}

test "MQTT connection rejects topic aliases beyond negotiated maximum" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer for (connection.outgoing_topic_aliases) |maybe_topic| {
        if (maybe_topic) |topic| std.testing.allocator.free(topic);
    };

    try std.testing.expectError(error.InvalidProperty, connection.publish("topic", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }},
    }));
    try std.testing.expectError(error.InvalidTopic, connection.publish("", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }},
    }));
    try connection.validateOutgoingTopicAlias("topic", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try connection.rememberOutgoingTopicAlias("topic", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
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
    try std.testing.expectError(error.InvalidProperty, connection.applyIncomingTopicAlias(&incoming));
}

test "MQTT runtime caps advertised topic alias maximum to local storage" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(u16, 0), effectiveTopicAliasMaximum(0));
    try std.testing.expectEqual(@as(u16, 4), effectiveTopicAliasMaximum(4));
    try std.testing.expectEqual(@as(u16, @intCast(topic_alias_slots)), effectiveTopicAliasMaximum(99));

    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{}, 99);
    try std.testing.expectEqual(@as(?u16, @intCast(topic_alias_slots)), mqtt.topicAliasMaximum(properties.items));

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{.{ .two_byte = .{
        .id = .topic_alias_maximum,
        .value = 8,
    } }}, 99);
    try std.testing.expectEqual(@as(usize, 0), properties.items.len);

    try std.testing.expectError(error.InvalidProperty, appendTopicAliasMaximumSetting(&properties, allocator, &.{.{ .two_byte = .{
        .id = .topic_alias_maximum,
        .value = @as(u16, @intCast(topic_alias_slots + 1)),
    } }}, 99));
}

test "MQTT connection enforces peer publish capabilities" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_maximum_qos = .at_most_once,
        .peer_retain_available = false,
    };

    try std.testing.expectError(error.InvalidQoS, connection.publish("topic", "payload", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidProperty, connection.publish("topic", "payload", .{ .retain = true }));

    connection.local_maximum_qos = .at_most_once;
    try std.testing.expectError(error.InvalidQoS, connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "qos/in",
        .packet_id = 7,
        .payload = "blocked",
    }));

    connection.local_maximum_qos = .exactly_once;
    connection.local_retain_available = false;
    try std.testing.expectError(error.InvalidProperty, connection.validateIncomingPublishCapabilities(.{
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

    try std.testing.expectEqual(mqtt.QoS.at_most_once, client.peer_maximum_qos);
    try std.testing.expect(!client.peer_retain_available);
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

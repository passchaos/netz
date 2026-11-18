//! MQTT connection state and packet exchange.

const std = @import("std");
const mqtt = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const AcceptOptions = runtime.AcceptOptions;
const AcceptedClient = runtime.AcceptedClient;
const BrokerEvent = runtime.BrokerEvent;
const Client = runtime.Client;
const ClientPacketEvent = runtime.ClientPacketEvent;
const ConnAckOptions = runtime.ConnAckOptions;
const ConnectAttempt = runtime.ConnectAttempt;
const ConnectOptions = runtime.ConnectOptions;
const ConnectionCapabilities = runtime.ConnectionCapabilities;
const ConnectionLimits = runtime.ConnectionLimits;
const Error = runtime.Error;
const Limits = runtime.Limits;
const OwnedAck = runtime.OwnedAck;
const OwnedAuth = runtime.OwnedAuth;
const OwnedConnAck = runtime.OwnedConnAck;
const OwnedConnect = runtime.OwnedConnect;
const OwnedDisconnect = runtime.OwnedDisconnect;
const OwnedPacket = runtime.OwnedPacket;
const OwnedPublish = runtime.OwnedPublish;
const OwnedSubAck = runtime.OwnedSubAck;
const OwnedSubscribe = runtime.OwnedSubscribe;
const OwnedUnsubAck = runtime.OwnedUnsubAck;
const OwnedUnsubscribe = runtime.OwnedUnsubscribe;
const PacketTransport = runtime.PacketTransport;
const PendingAcceptedClient = runtime.PendingAcceptedClient;
const PendingPacketState = runtime.PendingPacketState;
const PublishOptions = runtime.PublishOptions;
const Server = runtime.Server;
const SubscribeOptions = runtime.SubscribeOptions;
const TrafficCounters = runtime.TrafficCounters;
const TrafficStats = runtime.TrafficStats;
const UnsubscribeOptions = runtime.UnsubscribeOptions;
const applyConnAckNegotiation = runtime.applyConnAckNegotiation;
const auth_runtime = runtime.auth_runtime;
const broker_keep_alive = runtime.broker_keep_alive;
const connack_preparation = runtime.connack_preparation;
const deadline_policy = runtime.deadline_policy;
const earliestClockDeadline = runtime.earliestClockDeadline;
const http1_runtime = runtime.http1_runtime;
const keepAliveTimeout = runtime.keepAliveTimeout;
const listener_namespace = runtime.listener_namespace;
const negotiatedOutgoingInflightLimit = runtime.negotiatedOutgoingInflightLimit;
const packet_identifiers = runtime.packet_identifiers;
const packet_transport = runtime.packet_transport;
const problemInformationProperty = runtime.problemInformationProperty;
const proxy_protocol = runtime.proxy_protocol;
const termination = runtime.termination;
const tls_stream = runtime.tls_stream;
const topic_alias = runtime.topic_alias;
const validateAssignedClientIdentifierForConnect = runtime.validateAssignedClientIdentifierForConnect;
const websocket_runtime = runtime.websocket_runtime;
const write_property_staging_capacity = runtime.write_property_staging_capacity;

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
    session_expiry_interval: u32 = 0,
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
    /// Production Broker listeners can move inactivity scheduling to their
    /// shared deadline driver. Standalone runtime servers retain the ordinary
    /// per-read timeout APIs below.
    managed_keep_alive: broker_keep_alive.State = .{},
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
    /// A valid peer DISCONNECT stops network I/O while its already-buffered
    /// wire prefix and diagnostics remain available to the receive owner.
    peer_disconnect_received: std.atomic.Value(bool) = .init(false),
    /// Attached Broker readers finish the durable DISCONNECT decision before
    /// allowing automatic transport interruption. Immutable after attachment;
    /// standalone runtime connections retain immediate terminal shutdown.
    defer_peer_disconnect_shutdown: bool = false,
    peer_disconnect_shutdown_ready: std.atomic.Value(bool) = .init(false),
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
    /// Prepared before typed receive I/O or a correlated-response wait.
    /// Ordinary event decode retries use the separate inline slot below.
    pending_packets: ?*PendingPacketState = null,
    /// One complete packet retained until event decoding commits. This inline
    /// slot preserves retries without allocating ordinary event queues.
    retained_receive: @import("receive/packet_slot.zig").State = .{},
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
        self.retained_receive.deinit(self.allocator);
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

    pub fn clearWritePropertyOverflow(self: *Connection) void {
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
    /// error, shutdown, or valid DISCONNECT retires it permanently. Already
    /// queued packets preceding a peer DISCONNECT remain readable.
    pub fn isUsable(self: *const Connection) bool {
        return termination.usable(self);
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
        if (termination.shutdownDeferred(self)) return;
        self.transport_unusable.store(true, .release);
        try self.transport.interrupt();
    }

    /// The attached Broker owner has finished the peer's terminal decision,
    /// successfully or with a reported error. Wake writers before retirement
    /// takes their quiescence lock; this does not claim a durable success.
    pub fn completePeerDisconnect(self: *Connection) Error!void {
        self.peer_disconnect_shutdown_ready.store(true, .release);
        self.transport_unusable.store(true, .release);
        try self.transport.interrupt();
    }

    /// Begin shared broker inactivity scheduling after successful CONNACK.
    pub fn startManagedKeepAlive(self: *Connection) ?std.Io.Timestamp {
        return self.managed_keep_alive.start(
            self.transport.ioHandle(),
            keepAliveTimeout(self.keep_alive_seconds),
        );
    }

    pub fn managedKeepAliveDeadline(
        self: *const Connection,
    ) ?std.Io.Timestamp {
        if (self.peer_disconnect_received.load(.acquire)) return null;
        return self.managed_keep_alive.deadline();
    }

    /// Claim a deadline previously observed by the broker driver and interrupt
    /// the blocking transport read. Concurrent packet progress wins by first
    /// replacing the expected atomic value.
    pub fn expireManagedKeepAlive(
        self: *Connection,
        expected: std.Io.Timestamp,
    ) bool {
        if (self.peer_disconnect_received.load(.acquire)) return false;
        const expected_ns = std.math.cast(
            i64,
            expected.nanoseconds,
        ) orelse return false;
        if (!self.managed_keep_alive.claimExpired(expected_ns)) return false;
        self.transport_unusable.store(true, .release);
        self.transport.interrupt() catch {};
        return true;
    }

    pub fn managedKeepAliveTimedOut(self: *const Connection) bool {
        return self.managed_keep_alive.timedOut();
    }

    fn renewManagedKeepAlive(self: *Connection) void {
        self.managed_keep_alive.renew(
            self.transport.ioHandle(),
            keepAliveTimeout(self.keep_alive_seconds),
        );
    }

    fn renewManagedKeepAliveErased(context: *anyopaque) void {
        const self: *Connection = @ptrCast(@alignCast(context));
        self.renewManagedKeepAlive();
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

    pub fn clearProxyMetadata(self: *Connection) void {
        const metadata = self.proxy_metadata orelse return;
        metadata.deinit();
        self.allocator.destroy(metadata);
        self.proxy_metadata = null;
    }

    pub fn ensureIncomingTopicAliases(
        self: *Connection,
    ) std.mem.Allocator.Error!*topic_alias.Table {
        if (self.incoming_topic_aliases) |aliases| return aliases;
        const aliases = try self.allocator.create(topic_alias.Table);
        aliases.* = .{};
        self.incoming_topic_aliases = aliases;
        return aliases;
    }

    pub fn ensureOutgoingTopicAliases(
        self: *Connection,
    ) std.mem.Allocator.Error!*topic_alias.Table {
        if (self.outgoing_topic_aliases) |aliases| return aliases;
        const aliases = try self.allocator.create(topic_alias.Table);
        aliases.* = .{};
        self.outgoing_topic_aliases = aliases;
        return aliases;
    }

    pub fn clearTopicAliases(self: *Connection) void {
        self.clearIncomingTopicAliases();
        self.clearOutgoingTopicAliases();
    }

    pub fn clearIncomingTopicAliases(self: *Connection) void {
        if (self.incoming_topic_aliases) |aliases| {
            aliases.deinit(self.allocator);
            self.allocator.destroy(aliases);
            self.incoming_topic_aliases = null;
        }
    }

    pub fn clearOutgoingTopicAliases(self: *Connection) void {
        if (self.outgoing_topic_aliases) |aliases| {
            aliases.deinit(self.allocator);
            self.allocator.destroy(aliases);
            self.outgoing_topic_aliases = null;
        }
    }

    pub fn incomingTopicAlias(
        self: *const Connection,
        alias: u16,
    ) ?[]const u8 {
        const aliases = self.incoming_topic_aliases orelse return null;
        return aliases.get(alias);
    }

    pub fn outgoingTopicAlias(
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

    pub fn incomingConnectLevel(self: *const Connection) ?u8 {
        return if (self.capabilities.has_incoming_connect_level)
            self.incoming_connect_level_value
        else
            null;
    }

    pub fn setIncomingConnectLevel(
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

    /// Effective lifetime after the Network Connection ends. A successful
    /// MQTT 5 CONNACK can replace CONNECT's requested interval; DISCONNECT
    /// validation still uses the original CONNECT value.
    pub fn sessionExpiryInterval(self: *const Connection) u32 {
        return self.session_expiry_interval;
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

    pub fn setAssignedClientId(
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

    pub fn clearAssignedClientId(self: *Connection) void {
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

    pub fn acceptPendingBefore(
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
        (if (connect_deadline) |deadline|
            self.writeGeneratedPacketWithDeadline(
                self.write_scratch.items,
                .connect,
                deadline,
            )
        else
            self.writeGeneratedPacket(self.write_scratch.items, .connect)) catch |err| {
            if (self.isUsable()) {
                // Validation/deadline rejection before transport output can
                // retry CONNECT. Undo its connection-owned method and phase.
                self.authentication.deinit(allocator);
                self.authentication = .{};
            }
            return err;
        };
        // CONNECT has reached the transport. A consumed challenge or local
        // callback failure cannot safely restart this exchange on the socket.
        errdefer self.transport_unusable.store(true, .release);
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
                            self.sendAuthenticationProtocolErrorUntil(connect_deadline);
                        }
                        return err;
                    };
                    const response = try auth_handler.?.respond(
                        auth_handler.?.context,
                        auth,
                    );
                    // This property set came from the local callback. The
                    // attempt owner closes on failure without blaming the peer.
                    try self.authentication.validatePeerProperties(response);
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
                    if ((options.clean_start or options.client_id.len == 0) and value.session_present) {
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
                            self.sendAuthenticationProtocolErrorUntil(connect_deadline);
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
        const packet = try TypedReceive.read(self, .connect, null);
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
        const packet = try TypedReceive.read(self, .connect, deadline);
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
        self.session_expiry_interval = if (connect.protocol == .v5) self.connect_session_expiry else if (connect.clean_start) 0 else std.math.maxInt(u32);
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

    pub fn prepareConnAck(self: *Connection, options: ConnAckOptions) Error!connack_preparation.Prepared {
        return self.prepareConnAckMode(options, false);
    }

    fn prepareConnAckMode(self: *Connection, options: ConnAckOptions, reuse_scratch: bool) Error!connack_preparation.Prepared {
        if (!self.isUsable()) return error.ConnectionClosed;
        try self.validateOutgoingPacketType(.connack);
        try self.authentication.ensurePacketAllowed(.connack);
        return if (reuse_scratch) connack_preparation.prepareReusingScratch(self, options) else connack_preparation.prepare(self, options);
    }

    pub fn writePreparedConnAckMaybeBefore(
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
        var packet = try TypedReceive.read(self, .connack, null);
        errdefer packet.deinit(self.allocator);
        var connack = try mqtt.ConnAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer connack.deinit(self.allocator);
        try self.validateIncomingProperties(connack.properties);
        return .{ .packet = packet, .connack = connack };
    }

    pub fn publish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!void {
        const packet_id = try self.writePublish(topic, payload, options);
        if (packet_id) |id| try self.completePublish(id, options.qos);
    }

    pub const publishWithTimeout = PublishApi.publishWithTimeout;
    pub const publishWithDeadline = PublishApi.publishWithDeadline;
    pub const writePublishWithTimeout = PublishApi.writePublishWithTimeout;
    pub const writePublishWithDeadline = PublishApi.writePublishWithDeadline;
    pub const completePublishWithTimeout = PublishApi.completePublishWithTimeout;
    pub const completePublishWithDeadline = PublishApi.completePublishWithDeadline;
    pub const completePublishQoS2WithTimeout = PublishApi.completePublishQoS2WithTimeout;
    pub const completePublishQoS2WithDeadline = PublishApi.completePublishQoS2WithDeadline;
    pub const completePublishPubAckWithTimeout = PublishApi.completePublishPubAckWithTimeout;
    pub const completePublishPubAckWithDeadline = PublishApi.completePublishPubAckWithDeadline;
    pub const completePublishPubRecWithTimeout = PublishApi.completePublishPubRecWithTimeout;
    pub const completePublishPubRecWithDeadline = PublishApi.completePublishPubRecWithDeadline;
    pub const completePublishPubCompWithTimeout = PublishApi.completePublishPubCompWithTimeout;
    pub const completePublishPubCompWithDeadline = PublishApi.completePublishPubCompWithDeadline;

    pub fn writePublish(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions) Error!?u16 {
        return self.writePublishUntil(topic, payload, options, null);
    }

    fn writePublishUntil(self: *Connection, topic: []const u8, payload: []const u8, options: PublishOptions, deadline: ?std.Io.Clock.Timestamp) Error!?u16 {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.transport.ioHandle(), absolute);
        try self.validateOutgoingPublish(
            topic,
            options.qos,
            options.retain,
            options.properties,
        );

        const packet_id = if (options.qos == .at_most_once) null else try self.reserveOutgoingPublish(options.qos);
        errdefer if (packet_id) |id| self.releaseOutgoingPublish(id, options.qos);

        try self.writeValidatedPublishUntil(topic, payload, .{
            .qos = options.qos,
            .retain = options.retain,
            .dup = options.dup,
            .packet_id = packet_id,
            .properties = options.properties,
        }, deadline);
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
        transmission: @import("../session/mod.zig").Transmission,
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
        transmission: @import("../session/mod.zig").Transmission,
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
        transmission: @import("../session/mod.zig").Transmission,
    ) Error!void {
        return self.writeClientSessionTransmissionUntil(transmission, null);
    }

    pub fn writeClientSessionTransmissionWithDeadline(self: *Connection, transmission: @import("../session/mod.zig").Transmission, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return self.writeClientSessionTransmissionUntil(transmission, deadline);
    }

    fn writeClientSessionTransmissionUntil(self: *Connection, transmission: @import("../session/mod.zig").Transmission, deadline: ?std.Io.Clock.Timestamp) Error!void {
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
                return self.writeSessionPublishUntil(publish_value, deadline);
            },
            .pubrel => |pubrel| return self.writeSessionPubRelUntil(pubrel, deadline),
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
        try @import("../session/mod.zig").validatePublishForSession(
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
        value: @import("../session/mod.zig").PublishTransmission,
    ) Error!void {
        return self.writeSessionPublishUntil(value, null);
    }

    fn writeSessionPublishUntil(self: *Connection, value: @import("../session/mod.zig").PublishTransmission, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.transport.ioHandle(), absolute);
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
        self.writeValidatedPublishUntil(
            outgoing_topic,
            value.payload,
            write_options,
            deadline,
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
            return self.writeValidatedPublishUntil(
                value.topic,
                value.payload,
                fallback_options,
                deadline,
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
        return self.writeValidatedPublishUntil(topic, payload, options, null);
    }

    fn writeValidatedPublishUntil(self: *Connection, topic: []const u8, payload: []const u8, options: mqtt.PublishWriteOptions, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.transport.ioHandle(), absolute);
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
        if (deadline) |absolute| {
            self.transport.writePacketPartsWithDeadline(self.write_scratch.items, payload, absolute) catch |err| {
                self.transport_unusable.store(true, .release);
                return err;
            };
        } else try self.writeTransportPacketParts(self.write_scratch.items, payload);
        self.recordPacketSent(lengths.total);
    }

    pub fn writeSessionPubRel(
        self: *Connection,
        pubrel: @import("../session/mod.zig").PubRelTransmission,
    ) Error!void {
        return self.writeSessionPubRelUntil(pubrel, null);
    }

    fn writeSessionPubRelUntil(self: *Connection, pubrel: @import("../session/mod.zig").PubRelTransmission, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (deadline) |absolute| {
            var encoded: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
            try self.writeGeneratedPacketWithDeadline(try mqtt.AckPacket.writeNoPropertiesInto(&encoded, self.protocol, .pubrel, pubrel.packet_id, 0), .pubrel, absolute);
        } else try self.writePubRel(pubrel.packet_id, 0);
    }

    /// Complete QoS 1/2 without consuming unrelated application packets or
    /// known sibling acknowledgements. Interleaved packets remain bounded by
    /// the pending count/byte limits and are available to ordinary readers.
    pub fn completePublish(self: *Connection, packet_id: u16, qos: mqtt.QoS) Error!void {
        return self.completePublishUntil(packet_id, qos, null);
    }

    fn completePublishUntil(self: *Connection, packet_id: u16, qos: mqtt.QoS, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.transport.ioHandle(), absolute);
        switch (qos) {
            .at_most_once => return,
            .at_least_once => try PublishCompletion.puback(self, packet_id, deadline),
            .exactly_once => {
                const id = if (packet_id != 0 and self.packet_identifiers.contains(packet_id, .outgoing_qos2_pubrel)) packet_id else try PublishCompletion.pubrec(self, packet_id, deadline);
                try PublishCompletion.pubcomp(self, id, deadline);
            },
        }
    }

    pub fn completePublishPubAck(self: *Connection, packet_id: u16) Error!void {
        return PublishCompletion.puback(self, packet_id, null);
    }

    pub fn completePublishQoS2(self: *Connection, packet_id: u16) Error!void {
        return self.completePublishUntil(packet_id, .exactly_once, null);
    }

    pub fn completePublishPubRec(self: *Connection, packet_id: u16) Error!u16 {
        return PublishCompletion.pubrec(self, packet_id, null);
    }

    pub fn completePublishPubComp(self: *Connection, packet_id: u16) Error!void {
        return PublishCompletion.pubcomp(self, packet_id, null);
    }

    pub fn readPublish(self: *Connection) Error!OwnedPublish {
        const ready = try TypedReceive.front(self, .publish, null);
        const value = self.decodeIncomingPublish(ready.packet) catch |err| {
            if (err != error.OutOfMemory) {
                var packet = self.pending_packets.?.takeMatch(ready.index);
                packet.deinit(self.allocator);
            }
            return err;
        };
        _ = self.pending_packets.?.takeMatch(ready.index);
        return value;
    }

    fn decodeIncomingPublish(self: *Connection, packet: OwnedPacket) Error!OwnedPublish {
        return @import("receive/publish.zig").decode(self, packet, .{
            .ErrorType = Error,
            .PublishType = OwnedPublish,
            .validateUtf8 = validateIncomingUtf8,
            .validateProperties = validateIncomingProperties,
            .validateCapabilities = validateIncomingPublishCapabilities,
            .validateAlias = validateIncomingTopicAlias,
            .aliasTopic = incomingTopicAlias,
            .commit = commitValidatedIncomingPublish,
        });
    }

    pub fn writePubAck(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacketNoProperties(.puback, packet_id, reason_code);
        self.completeIncomingPublish(.puback, packet_id);
    }

    pub fn writePubAckWithDeadline(self: *Connection, packet_id: u16, reason_code: u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.writeIncomingAckWithDeadline(.puback, packet_id, reason_code, deadline);
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

    /// Whether this Network Connection currently owns an outbound PUBLISH,
    /// SUBSCRIBE or UNSUBSCRIBE transaction with this Packet Identifier. Broker
    /// event loops use this before applying an acknowledgement so an unknown
    /// identifier can be ignored without weakening wrong-stage validation.
    pub fn hasOutgoingPacketIdentifier(
        self: *const Connection,
        packet_id: u16,
    ) bool {
        return packet_id != 0 and
            self.packet_identifiers.containsOutgoing(packet_id);
    }

    /// Share a live durable sender index without copying it into wire QoS
    /// counters. The caller detaches it before replacing the owning Session.
    pub fn setOutgoingPacketIdentifierOwner(self: *Connection, owner: ?packet_identifiers.Ownership) Error!void {
        return self.packet_identifiers.setExternalOutgoing(self.allocator, owner);
    }

    pub fn readPubAck(self: *Connection) Error!OwnedAck {
        return self.readAck(.puback);
    }

    const AckApplication = @import("acknowledgement/apply.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const release = Connection.releaseOutgoingPublish;
        pub const writePubRel = Connection.writePubRelUntil;
    });

    /// Apply a PUBACK that was parsed by `readBrokerEvent`.
    ///
    /// Broker readers must demultiplex inbound packets before knowing which
    /// typed operation to invoke. Keeping state mutation here preserves the
    /// same unsolicited/negative-ack checks as the synchronous client path.
    pub const applyPubAck = AckApplication.puback;

    /// Apply a validated PUBREC and send PUBREL before committing its QoS 2
    /// stage. The caller serializes this with other connection writes.
    pub const applyPubRec = AckApplication.pubrec;
    const applyPubRecUntil = AckApplication.pubrecUntil;

    /// Apply a validated PUBCOMP and release its completed QoS 2 exchange.
    pub const applyPubComp = AckApplication.pubcomp;

    pub fn writePubRec(self: *Connection, packet_id: u16, reason_code: u8) Error!void {
        try self.writeAckPacketNoProperties(.pubrec, packet_id, reason_code);
        self.completeIncomingPubRec(packet_id, reason_code);
    }

    pub fn writePubRecWithDeadline(self: *Connection, packet_id: u16, reason_code: u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.writeIncomingAckWithDeadline(.pubrec, packet_id, reason_code, deadline);
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

    fn writePubRelUntil(self: *Connection, packet_id: u16, dup: bool, deadline: ?std.Io.Clock.Timestamp) Error!void {
        var encoded: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
        const bytes = try mqtt.AckPacket.writeNoPropertiesIntoWithDup(&encoded, self.protocol, .pubrel, dup, packet_id, 0);
        if (deadline) |absolute| try self.writeGeneratedPacketWithDeadline(bytes, .pubrel, absolute) else try self.writeGeneratedPacket(bytes, .pubrel);
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

    pub fn writePubCompWithDeadline(self: *Connection, packet_id: u16, reason_code: u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.writeIncomingAckWithDeadline(.pubcomp, packet_id, reason_code, deadline);
    }

    /// Receive credit changes only after the complete acknowledgement write.
    fn writeIncomingAckWithDeadline(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16, reason_code: u8, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        var encoded: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
        const bytes = try mqtt.AckPacket.writeNoPropertiesInto(&encoded, self.protocol, packet_type, packet_id, reason_code);
        try self.writeGeneratedPacketWithDeadline(bytes, packet_type, deadline);
        if (packet_type == .pubrec) self.completeIncomingPubRec(packet_id, reason_code) else self.completeIncomingPublish(packet_type, packet_id);
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
        return ControlExchange.subscribe(self, subscriptions, options, null);
    }

    /// One timeout spans SUBSCRIBE output and SUBACK input, including any
    /// intervening MQTT traffic retained for later ordinary reads.
    pub fn subscribeWithTimeout(self: *Connection, subscriptions: []const mqtt.Subscription, options: SubscribeOptions, timeout: std.Io.Duration) Error!OwnedSubAck {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.subscribeWithDeadline(subscriptions, options, self.transport.deadlineFromNow(timeout));
    }

    pub fn subscribeWithDeadline(self: *Connection, subscriptions: []const mqtt.Subscription, options: SubscribeOptions, deadline: std.Io.Clock.Timestamp) Error!OwnedSubAck {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return ControlExchange.subscribe(self, subscriptions, options, deadline);
    }

    pub fn readSubscribe(self: *Connection) Error!OwnedSubscribe {
        var packet = try TypedReceive.read(self, .subscribe, null);
        errdefer packet.deinit(self.allocator);
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
        return ControlCompletion.readSubAck(self);
    }

    /// Borrow complete packet storage until the control reader commits it.
    fn parseReadSubAck(self: *Connection, packet: OwnedPacket) Error!OwnedSubAck {
        if (packet.fixed.packet_type != .suback) return error.UnexpectedPacket;
        var suback = try mqtt.SubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer suback.deinit(self.allocator);
        try self.validateIncomingProperties(suback.properties);
        try ControlCompletion.finish(self, .suback, suback.packet_id, suback.reason_codes);
        return .{ .packet = packet, .suback = suback };
    }

    pub fn unsubscribe(self: *Connection, topic_filters: []const []const u8, options: UnsubscribeOptions) Error!OwnedUnsubAck {
        return ControlExchange.unsubscribe(self, topic_filters, options, null);
    }

    /// One timeout spans UNSUBSCRIBE output and its correlated UNSUBACK.
    pub fn unsubscribeWithTimeout(self: *Connection, topic_filters: []const []const u8, options: UnsubscribeOptions, timeout: std.Io.Duration) Error!OwnedUnsubAck {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.unsubscribeWithDeadline(topic_filters, options, self.transport.deadlineFromNow(timeout));
    }

    pub fn unsubscribeWithDeadline(self: *Connection, topic_filters: []const []const u8, options: UnsubscribeOptions, deadline: std.Io.Clock.Timestamp) Error!OwnedUnsubAck {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return ControlExchange.unsubscribe(self, topic_filters, options, deadline);
    }

    pub fn readUnsubscribe(self: *Connection) Error!OwnedUnsubscribe {
        var packet = try TypedReceive.read(self, .unsubscribe, null);
        errdefer packet.deinit(self.allocator);
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
        return ControlCompletion.readUnsubAck(self);
    }

    fn parseReadUnsubAck(
        self: *Connection,
        packet: OwnedPacket,
    ) Error!OwnedUnsubAck {
        if (packet.fixed.packet_type != .unsuback) return error.UnexpectedPacket;
        var unsuback = try mqtt.UnsubAck.parse(self.allocator, self.protocol, packet.bytes);
        errdefer unsuback.deinit(self.allocator);
        try self.validateIncomingProperties(unsuback.properties);
        try ControlCompletion.finish(self, .unsuback, unsuback.packet_id, unsuback.reason_codes);
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
        if (deadline) |absolute|
            try self.writePingReqWithDeadline(absolute)
        else
            try self.writePingReq();
        var packet = try AckReader.read(self, .pingresp, deadline);
        defer packet.deinit(self.allocator);
        try mqtt.validatePing(packet.bytes, true);
    }

    pub fn readPingReq(self: *Connection) Error!void {
        var packet = try TypedReceive.read(self, .pingreq, null);
        defer packet.deinit(self.allocator);
        try mqtt.validatePing(packet.bytes, false);
    }

    const PingSender = @import("ping.zig").Sender(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const validate = Connection.validateOutgoingPacketType;
        pub const write = Connection.writeGeneratedPacket;
        pub const writeDeadline = Connection.writeGeneratedPacketWithDeadline;
    });

    pub const writePingResp = PingSender.writePingResp;
    pub const writePingRespWithTimeout = PingSender.writePingRespWithTimeout;
    pub const writePingRespWithDeadline = PingSender.writePingRespWithDeadline;

    /// Emit a PINGREQ without consuming the socket. Event-loop owners use
    /// this split operation so the same receive path can continue delivering
    /// application packets while it waits for PINGRESP.
    pub const writePingReq = PingSender.writePingReq;
    pub const writePingReqWithTimeout = PingSender.writePingReqWithTimeout;
    pub const writePingReqWithDeadline = PingSender.writePingReqWithDeadline;

    /// Drop connection-local acknowledgement bookkeeping while preserving all
    /// negotiated limits. Durable clients keep QoS state in their Session
    /// store instead, so every new Network Connection starts with empty wire
    /// inflight tables even when CONNACK reports Session Present.
    pub fn resetPacketIdentifiers(self: *Connection) void {
        self.next_packet_id = 1;
        self.outgoing_inflight = 0;
        self.incoming_inflight = 0;
        self.packet_identifiers.clearRetainingCapacity(self.allocator);
    }

    pub fn disconnect(self: *Connection, reason_code: u8) Error!void {
        try self.writeDisconnectWithProperties(reason_code, &.{});
    }

    const DisconnectWriter = @import("disconnect.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const validate = Connection.validateOutgoingDisconnect;
        pub const generate = Connection.writeGeneratedPacket;
        pub const generateBefore = Connection.writeGeneratedPacketWithDeadline;
    });

    pub const writeDisconnectWithProperties = DisconnectWriter.write;
    pub const writeDisconnectWithDeadline = DisconnectWriter.withDeadline;
    pub const writeDisconnectWithTimeout = DisconnectWriter.withTimeout;

    pub fn validateOutgoingDisconnect(
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

    pub fn validateIncomingDisconnect(
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

    /// Read the peer's terminal diagnostic, including one retained by a typed
    /// reader expecting a different packet. Local decoding allocation failure
    /// leaves the complete packet available for retry.
    pub fn readDisconnect(self: *Connection) Error!OwnedDisconnect {
        if (!termination.canReadBuffered(self)) return error.ConnectionClosed;
        if (self.retained_receive.packet()) |packet| {
            if (packet.fixed.packet_type == .disconnect) return EventReceive.retainedDisconnect(self);
        }
        const ready = try TypedReceive.front(self, .disconnect, null);
        return EventReceive.disconnect(self, ready);
    }

    fn finishIncomingDisconnect(self: *Connection, disconnect_packet: mqtt.Disconnect) void {
        if (mqtt.sessionExpiryInterval(disconnect_packet.properties)) |interval| self.session_expiry_interval = interval;
        termination.receivedDisconnect(self);
        // Ordinary readers have consumed the wire prefix. Only packets
        // following this terminal packet remain in the pending queue.
        self.clearPendingPacketState();
    }

    fn decodeIncomingDisconnect(
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

    pub fn writeAuthWithDeadline(
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

    pub fn validateOutgoingAuthReason(
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

    pub fn parseIncomingAuth(
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
    /// validated before the exchange starts. The previous authenticated
    /// session continues carrying ordinary MQTT traffic during this exchange.
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

    pub const ReauthenticationStep = struct { auth: OwnedAuth, complete: bool };

    /// Receive one re-authentication continuation/completion packet.
    pub fn receiveReauthentication(
        self: *Connection,
    ) Error!ReauthenticationStep {
        return self.receiveReauthenticationUntil(null);
    }

    /// Wait for the next reauthentication step within one absolute budget.
    /// Other packets remain available in wire order to normal event readers.
    pub fn receiveReauthenticationWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!ReauthenticationStep {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return self.receiveReauthenticationUntil(deadline);
    }

    pub fn receiveReauthenticationWithTimeout(self: *Connection, timeout: std.Io.Duration) Error!ReauthenticationStep {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveReauthenticationWithDeadline(self.transport.deadlineFromNow(timeout));
    }

    fn receiveReauthenticationUntil(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!ReauthenticationStep {
        if (self.authentication.phase != .reauthenticating) return error.InvalidAuthenticationState;
        var auth = try ReauthenticationReader.read(self, deadline);
        errdefer auth.deinit(self.allocator);
        const complete = try self.applyAuthenticationEventUntil(auth.auth, deadline);
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
        return self.applyAuthenticationEventUntil(auth, null);
    }

    pub fn applyAuthenticationEventWithDeadline(self: *Connection, auth: mqtt.Auth, deadline: std.Io.Clock.Timestamp) Error!bool {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return self.applyAuthenticationEventUntil(auth, deadline);
    }

    fn applyAuthenticationEventUntil(self: *Connection, auth: mqtt.Auth, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        if (auth.reason_code == 0x19) {
            self.authentication.beginReauthentication(
                auth.properties,
            ) catch |err| {
                if (err == error.AuthenticationMethodMismatch or
                    err == error.AuthenticationNotConfigured or
                    err == error.InvalidAuthenticationState)
                {
                    self.sendAuthenticationProtocolErrorUntil(deadline);
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
                self.sendAuthenticationProtocolErrorUntil(deadline);
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
        return self.continueReauthenticationUntil(reason_code, properties, null);
    }

    /// Continue with a complete AUTH property set under one awake-clock budget.
    pub fn continueReauthenticationWithDeadline(self: *Connection, reason_code: u8, properties: []const mqtt.Property, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return self.continueReauthenticationUntil(reason_code, properties, deadline);
    }

    fn continueReauthenticationUntil(self: *Connection, reason_code: u8, properties: []const mqtt.Property, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.authentication.phase != .reauthenticating) {
            return error.InvalidAuthenticationState;
        }
        if (reason_code != 0 and reason_code != 0x18) {
            return error.InvalidAuthenticationState;
        }
        try self.authentication.validatePeerProperties(properties);
        try self.writeAuthMaybeBefore(reason_code, properties, deadline);
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

    /// Accept a peer's Re-authenticate request while retaining ordinary traffic
    /// under the existing authenticated identity.
    pub fn acceptReauthentication(
        self: *Connection,
    ) Error!OwnedAuth {
        return self.acceptReauthenticationUntil(null);
    }

    pub fn acceptReauthenticationWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!OwnedAuth {
        _ = try deadline_policy.usableAwake(self.transport.ioHandle(), deadline);
        return self.acceptReauthenticationUntil(deadline);
    }

    pub fn acceptReauthenticationWithTimeout(self: *Connection, timeout: std.Io.Duration) Error!OwnedAuth {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptReauthenticationWithDeadline(self.transport.deadlineFromNow(timeout));
    }

    fn acceptReauthenticationUntil(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!OwnedAuth {
        if (self.authentication.phase != .active) return error.InvalidAuthenticationState;
        var auth = try ReauthenticationReader.read(self, deadline);
        errdefer auth.deinit(self.allocator);
        if (auth.auth.reason_code != 0x19) {
            self.sendAuthenticationProtocolErrorUntil(deadline);
            return error.InvalidAuthenticationState;
        }
        self.authentication.beginReauthentication(
            auth.auth.properties,
        ) catch |err| {
            if (err == error.AuthenticationMethodMismatch) {
                self.sendAuthenticationProtocolErrorUntil(deadline);
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
        var packet = try TypedReceive.read(self, .auth, deadline);
        errdefer packet.deinit(self.allocator);
        return self.parseReadAuth(packet);
    }

    fn parseReadAuth(self: *Connection, packet: OwnedPacket) Error!OwnedAuth {
        if (packet.fixed.packet_type != .auth) return error.UnexpectedPacket;
        const auth_packet = try self.parseIncomingAuth(packet.bytes);
        return .{ .packet = packet, .auth = auth_packet };
    }

    fn observeDisconnectPacket(self: *Connection, packet: OwnedPacket) Error!bool {
        if (packet.fixed.packet_type != .disconnect) return false;
        var value = try self.decodeIncomingDisconnect(packet.bytes);
        if (mqtt.sessionExpiryInterval(value.properties)) |interval| self.session_expiry_interval = interval;
        value.deinit(self.allocator);
        termination.receivedDisconnect(self);
        return true;
    }

    fn observeQueuedDisconnect(self: *Connection) Error!bool {
        if (try self.observeRetainedDisconnect()) return true;
        const pending = self.pending_packets orelse return false;
        const Match = struct {
            fn matches(_: void, packet: OwnedPacket) bool {
                return packet.fixed.packet_type == .disconnect;
            }
        };
        const found = pending.findFirstMatching({}, Match.matches) orelse return false;
        _ = try self.observeDisconnectPacket(found.packet);
        pending.keepThrough(self.allocator, found.index);
        return true;
    }

    fn observeRetainedDisconnect(self: *Connection) Error!bool {
        const packet = self.retained_receive.packet() orelse return false;
        return self.observeDisconnectPacket(packet);
    }

    /// Read one broker-facing packet while preserving transport-independent
    /// connection validation and inflight state.
    pub fn readBrokerEvent(self: *Connection) Error!BrokerEvent {
        return self.readBrokerEventInternal(null);
    }

    /// Read one broker-facing event while allowing a complete short TCP
    /// packet to borrow `storage` until the returned event is deinitialized.
    /// DISCONNECT, TLS and WebSocket packets retain owned behavior so terminal
    /// diagnostics can survive a local decoding failure.
    /// Callers must not reuse `storage` before `BrokerEvent.deinit`.
    /// On decode allocation failure, the connection restores those bytes to
    /// its own read-ahead; callers may immediately reuse `storage` and retry.
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
        return self.readBrokerEventOptions(.{ .deadline = deadline });
    }

    /// Read one packet valid on an established client connection. Unlike the
    /// synchronous typed helpers, this preserves packet ordering while a
    /// single owner multiplexes publications, QoS acknowledgements, liveness,
    /// server DISCONNECT, and enhanced authentication.
    pub fn readClientPacketEvent(
        self: *Connection,
    ) Error!ClientPacketEvent {
        return self.readClientPacketEventOptions(.{});
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
        return self.readClientPacketEventOptions(.{ .deadline = deadline });
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
        return self.readClientPacketEventOptions(.{ .deadline = deadline });
    }

    fn readClientPacketEventOptions(self: *Connection, options: EventReceiveOptions) Error!ClientPacketEvent {
        return switch (try EventReceive.read(self, options)) {
            .disconnect => |value| .{ .disconnect = value },
            .packet => |input| blk: {
                const event = self.finishClientPacketEvent(input.packet) catch |err| {
                    input.reject(self, err);
                    return err;
                };
                input.commit(self);
                break :blk event;
            },
        };
    }

    fn finishClientPacketEvent(
        self: *Connection,
        packet_value: OwnedPacket,
    ) Error!ClientPacketEvent {
        const packet = packet_value;
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
                break :blk .{ .publish = try self.decodeIncomingPublish(packet) };
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
            .disconnect => unreachable, // Decoded while retained by EventReceive.
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
        try self.readBrokerEventOptionsOut(.{
            .inactivity_timeout = keepAliveTimeout(self.keep_alive_seconds),
            .storage = storage,
            .prefix_len = prefix_len,
        }, out);
    }

    /// Broker hot path backed by one shared lifecycle deadline driver rather
    /// than one timer arm/clear around every socket read. Large packet progress
    /// renews through the observer; a complete packet renews after validation.
    pub fn readBrokerEventWithManagedKeepAliveIntoPrefixedOut(
        self: *Connection,
        storage: []u8,
        prefix_len: usize,
        out: *BrokerEvent,
    ) Error!void {
        self.readBrokerEventOptionsOut(.{
            .inactivity_observer = .{
                .context = self,
                .renew_fn = renewManagedKeepAliveErased,
            },
            .storage = storage,
            .prefix_len = prefix_len,
        }, out) catch |err| {
            if (self.managedKeepAliveTimedOut()) return error.Timeout;
            return err;
        };
        self.renewManagedKeepAlive();
        if (self.managedKeepAliveTimedOut()) {
            out.deinit(self.allocator);
            return error.Timeout;
        }
    }

    fn readBrokerEventInternal(
        self: *Connection,
        inactivity_timeout: ?std.Io.Clock.Duration,
    ) Error!BrokerEvent {
        return self.readBrokerEventOptions(.{ .inactivity_timeout = inactivity_timeout });
    }

    fn readBrokerEventInternalInto(
        self: *Connection,
        inactivity_timeout: ?std.Io.Clock.Duration,
        storage: []u8,
    ) Error!BrokerEvent {
        return self.readBrokerEventOptions(.{ .inactivity_timeout = inactivity_timeout, .storage = storage });
    }

    fn readBrokerEventOptions(self: *Connection, options: EventReceiveOptions) Error!BrokerEvent {
        var event: BrokerEvent = undefined;
        try self.readBrokerEventOptionsOut(options, &event);
        return event;
    }

    fn readBrokerEventOptionsOut(self: *Connection, options: EventReceiveOptions, out: *BrokerEvent) Error!void {
        switch (try EventReceive.read(self, options)) {
            .disconnect => |value| out.* = .{ .disconnect = value },
            .packet => |input| {
                self.finishBrokerEventInto(input.packet, out) catch |err| {
                    input.reject(self, err);
                    return err;
                };
                input.commit(self);
            },
        }
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
                const value = try self.decodeIncomingPublish(packet);
                out.* = .{ .publish = value };
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
            .disconnect => unreachable, // Decoded while retained by EventReceive.
            else => return error.UnexpectedPacket,
        }
    }

    pub fn validateOutgoingTopicAlias(self: *Connection, topic: []const u8, properties: []const mqtt.Property) Error!void {
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

    pub fn prepareOutgoingTopicAliasCommit(
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

    pub fn applyIncomingTopicAlias(
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

    pub fn commitIncomingPublish(
        self: *Connection,
        publish_packet: *mqtt.Publish,
    ) Error!void {
        try self.validateIncomingPublishCapabilities(publish_packet.*);
        try self.validateIncomingTopicAlias(publish_packet.*);
        return self.commitValidatedIncomingPublish(publish_packet, true);
    }

    fn commitValidatedIncomingPublish(self: *Connection, publish_packet: *mqtt.Publish, update_alias: bool) Error!void {
        const recorded = try self.recordIncomingPublish(publish_packet.*);
        errdefer if (recorded) {
            const packet_id = publish_packet.packet_id.?;
            const stage: packet_identifiers.State.Stage = switch (publish_packet.qos) {
                .at_most_once => unreachable,
                .at_least_once => .incoming_qos1,
                .exactly_once => .incoming_qos2,
            };
            std.debug.assert(self.packet_identifiers.remove(self.allocator, packet_id, stage));
            self.incoming_inflight -= 1;
        };
        if (update_alias) try self.applyValidatedIncomingTopicAlias(publish_packet);
    }

    pub fn validateIncomingPublishCapabilities(self: Connection, publish_packet: mqtt.Publish) Error!void {
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

    pub fn validateIncomingConnectUtf8(
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

    pub fn validateIncomingUtf8(
        self: Connection,
        value: []const u8,
    ) Error!void {
        if (self.strict_utf8) try mqtt.validateStrictUtf8String(value);
    }

    pub fn validateIncomingProperties(
        self: Connection,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.strict_utf8) {
            try mqtt.validateStrictUtf8Properties(properties);
        }
    }

    pub fn validateIncomingSubscriptionsUtf8(
        self: Connection,
        subscriptions: []const mqtt.Subscription,
    ) Error!void {
        if (!self.strict_utf8) return;
        for (subscriptions) |subscription| {
            try mqtt.validateStrictUtf8String(subscription.topic_filter);
        }
    }

    pub fn validateIncomingTopicFiltersUtf8(
        self: Connection,
        topic_filters: []const []const u8,
    ) Error!void {
        if (!self.strict_utf8) return;
        for (topic_filters) |filter| {
            try mqtt.validateStrictUtf8String(filter);
        }
    }

    const PublishDirection = enum { incoming, outgoing };

    pub fn validatePublishPropertyDirection(
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

    pub fn validateIncomingPubRel(self: Connection, packet_id: u16) Error!void {
        // A PUBREL is valid only after this endpoint has received a QoS 2
        // PUBLISH with the same Packet Identifier and answered PUBREC.  Rumqtt
        // treats an unsolicited PUBREL as a state error; preserve that guard so
        // peer bugs cannot complete or disturb unrelated QoS state.
        if (!self.packet_identifiers.contains(
            packet_id,
            .incoming_qos2,
        )) return error.InvalidPacketIdentifier;
    }

    pub fn recordIncomingPublish(self: *Connection, publish_packet: mqtt.Publish) Error!bool {
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

    pub fn completeIncomingPublish(self: *Connection, packet_type: mqtt.PacketType, packet_id: u16) void {
        const stage: packet_identifiers.State.Stage = switch (packet_type) {
            .puback => .incoming_qos1,
            .pubcomp => .incoming_qos2,
            else => return,
        };
        if (!self.packet_identifiers.remove(self.allocator, packet_id, stage)) return;
        self.incoming_inflight -= 1;
    }

    pub fn completeIncomingPubRec(self: *Connection, packet_id: u16, reason_code: u8) void {
        // MQTT 5 negative PUBREC reason codes terminate the QoS 2 handshake:
        // the sender must not continue with PUBREL.  Release the receive slot
        // immediately, while success and "No matching subscribers" continue
        // through PUBREL/PUBCOMP like rumqtt's QoS2 state machine.
        if (reason_code >= 0x80) self.completeIncomingPublish(.pubcomp, packet_id);
    }

    pub fn validateOutgoingSubscribe(self: Connection, subscriptions: []const mqtt.Subscription, properties: []const mqtt.Property) Error!void {
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

    pub fn validateIncomingSubscribe(self: Connection, subscriptions: []const mqtt.Subscription, properties: []const mqtt.Property) Error!void {
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

    pub fn writePacket(self: *Connection, bytes: []u8) Error!void {
        if (!self.isUsable()) return error.ConnectionClosed;
        const fixed = try mqtt.FixedHeader.parse(bytes);
        try mqtt.validatePacketFlags(self.protocol, fixed);
        try self.validatePacketForWrite(fixed.packet_type, bytes.len);
        try self.writeTransportPacket(bytes);
        self.recordPacketSent(bytes.len);
        if (fixed.packet_type == .disconnect) termination.sentDisconnect(self);
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
        if (packet_type == .disconnect) termination.sentDisconnect(self);
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
        if (packet_type == .disconnect) termination.sentDisconnect(self);
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

    pub fn readPacket(self: *Connection) Error!OwnedPacket {
        if (!termination.canReadBuffered(self)) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        if (!self.isUsable()) return error.ConnectionClosed;
        return self.readTransportPacket();
    }

    fn readTransportPacket(self: *Connection) Error!OwnedPacket {
        const packet = try self.readUnvalidatedTransportPacket();
        return self.finishReadPacket(packet);
    }

    fn readUnvalidatedTransportPacket(
        self: *Connection,
    ) Error!packet_transport.OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (try self.observeRetainedDisconnect()) return error.ConnectionClosed;
        if (self.retained_receive.bytes != null) return self.retained_receive.take();
        var packet = try self.transport.readPacket(
            self.allocator,
            self.limits.max_packet_size,
        );
        if (!packet.traffic_recorded) self.recordPacketReceived(packet.bytes.len);
        packet.traffic_recorded = true;
        return packet;
    }

    pub fn readPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedPacket {
        if (!termination.canReadBuffered(self)) return error.ConnectionClosed;
        if (self.popPendingPacket()) |packet| return packet;
        if (!self.isUsable()) return error.ConnectionClosed;
        return self.readTransportPacketWithDeadline(deadline);
    }

    fn readTransportPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedPacket {
        const packet = try self.readUnvalidatedTransportPacketWithDeadline(
            deadline,
        );
        return self.finishReadPacketUntil(packet, deadline);
    }

    fn readUnvalidatedTransportPacketWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!packet_transport.OwnedPacket {
        if (!self.isUsable()) return error.ConnectionClosed;
        if (try self.observeRetainedDisconnect()) return error.ConnectionClosed;
        if (self.retained_receive.bytes != null) return self.retained_receive.take();
        var packet = try self.transport.readPacketWithDeadline(
            self.allocator,
            self.limits.max_packet_size,
            deadline,
        );
        if (!packet.traffic_recorded) self.recordPacketReceived(packet.bytes.len);
        packet.traffic_recorded = true;
        return packet;
    }

    pub fn recordPacketReceived(self: *Connection, bytes: usize) void {
        self.traffic.recordReceivedExclusive(bytes);
        if (!self.traffic_sink_deferred) {
            if (self.traffic_sink) |counters| counters.recordReceived(bytes);
        }
    }

    pub fn recordPacketSent(self: *Connection, bytes: usize) void {
        self.traffic.recordSentExclusive(bytes);
        if (!self.traffic_sink_deferred) {
            if (self.traffic_sink) |counters| counters.recordSent(bytes);
        }
    }

    pub fn pendingPacketCount(self: *const Connection) usize {
        const pending = self.pending_packets orelse return 0;
        return pending.count();
    }

    pub fn ensurePendingPacketQueueAvailable(self: *Connection) Error!void {
        if (self.limits.max_pending_ping_packets == 0 or
            self.limits.max_pending_packet_bytes == 0)
        {
            return error.TooManyPendingPackets;
        }
        try self.ensurePendingPacketStorage();
        return self.pending_packets.?.ensureAvailable(self.limits.max_pending_ping_packets, self.limits.max_pending_packet_bytes);
    }

    fn ensurePendingPacketStorage(self: *Connection) Error!void {
        if (self.pending_packets == null) {
            const pending = try self.allocator.create(PendingPacketState);
            pending.* = .{};
            self.pending_packets = pending;
        }
        if (self.retained_receive.packet()) |packet| {
            if (packet.fixed.packet_type != .disconnect) {
                try self.pending_packets.?.prependRetained(self.allocator, packet);
                _ = self.retained_receive.take();
            }
        }
    }

    const AckReader = @import("acknowledgement/wait.zig").Reader(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const ErrorType = Error;
        pub const readPacket = Connection.readTransportPacket;
        pub const readPacketWithDeadline = Connection.readTransportPacketWithDeadline;
        pub const queuePacket = Connection.queuePendingPacket;
        pub const observeDisconnect = Connection.observeDisconnectPacket;

        pub fn retainOverflow(connection: *Connection, packet: OwnedPacket) void {
            connection.pending_packets.?.retainOverflow(packet);
        }
    });

    const TypedReceive = @import("receive/retained.zig").Reader(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const ErrorType = Error;
        pub const canReadBuffered = termination.canReadBuffered;
        pub const prepareStorage = Connection.ensurePendingPacketStorage;
        pub const readPacket = Connection.readTransportPacket;
        pub const readPacketWithDeadline = Connection.readTransportPacketWithDeadline;
        pub const observeDisconnect = Connection.observeDisconnectPacket;
        pub const observeRetainedDisconnect = Connection.observeRetainedDisconnect;
    });

    const EventReceiveOptions = @import("receive/events.zig").Options;
    const EventReceive = @import("receive/events.zig").Reader(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const DisconnectType = OwnedDisconnect;
        pub const ErrorType = Error;
        pub const canReadBuffered = termination.canReadBuffered;
        pub const recordReceived = Connection.recordPacketReceived;
        pub const validate = Connection.validateReadPacketUntil;
        pub const decodeDisconnect = Connection.decodeIncomingDisconnect;
        pub const finishDisconnect = Connection.finishIncomingDisconnect;
    });

    const ReauthenticationReader = @import("auth_receive.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const AuthType = OwnedAuth;
        pub const ErrorType = Error;
        pub const canReadBuffered = termination.canReadBuffered;
        pub const observeRetainedDisconnect = Connection.observeRetainedDisconnect;
        pub const prepare = Connection.ensurePendingPacketQueueAvailable;
        pub const prepareStorage = Connection.ensurePendingPacketStorage;
        pub const parse = Connection.parseReadAuth;
        pub const readPacket = Connection.readTransportPacket;
        pub const readPacketWithDeadline = Connection.readTransportPacketWithDeadline;
        pub const queuePacket = Connection.queuePendingPacket;
        pub fn validateDisconnect(connection: *Connection, bytes: []const u8) Error!void {
            var packet = try connection.decodeIncomingDisconnect(bytes);
            if (mqtt.sessionExpiryInterval(packet.properties)) |interval| connection.session_expiry_interval = interval;
            packet.deinit(connection.allocator);
            termination.receivedDisconnect(connection);
        }
        pub fn retainOverflow(connection: *Connection, packet: OwnedPacket) void {
            connection.pending_packets.?.retainOverflow(packet);
        }
    });

    const PublishCompletion = @import("acknowledgement/publish.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const AckType = OwnedAck;
        pub const ErrorType = Error;
        pub const canReadBuffered = termination.canReadBuffered;
        pub const observeDisconnect = Connection.observeDisconnectPacket;
        pub const observeQueuedDisconnect = Connection.observeQueuedDisconnect;
        pub const prepareQueue = Connection.ensurePendingPacketQueueAvailable;
        pub const prepareStorage = Connection.ensurePendingPacketStorage;
        pub const readPacket = Connection.readTransportPacket;
        pub const readPacketWithDeadline = Connection.readTransportPacketWithDeadline;
        pub const queuePacket = Connection.queuePendingPacket;
        pub const parseAck = Connection.parseReadAck;
        pub const applyPubAck = Connection.applyPubAck;
        pub const applyPubRec = Connection.applyPubRecUntil;
        pub const applyPubComp = Connection.applyPubComp;

        pub fn contains(connection: *const Connection, packet_id: u16, stage: packet_identifiers.State.Stage) bool {
            return connection.packet_identifiers.contains(packet_id, stage);
        }

        pub fn hasOutgoing(connection: *const Connection, packet_id: u16) bool {
            return connection.packet_identifiers.containsOutgoingPublish(packet_id);
        }
    });

    const PublishApi = @import("acknowledgement/publish_api.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const OptionsType = PublishOptions;
        pub const prepareQueue = Connection.ensurePendingPacketQueueAvailable;
        pub const writePublish = Connection.writePublishUntil;
        pub const complete = Connection.completePublishUntil;
        pub const puback = PublishCompletion.puback;
        pub const pubrec = PublishCompletion.pubrec;
        pub const pubcomp = PublishCompletion.pubcomp;
    });

    const ControlExchange = @import("acknowledgement/exchange.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const SubAckType = OwnedSubAck;
        pub const UnsubAckType = OwnedUnsubAck;
        pub const SubscribeOptionsType = SubscribeOptions;
        pub const UnsubscribeOptionsType = UnsubscribeOptions;
        pub const validateType = Connection.validateOutgoingPacketType;
        pub const validateSubscribe = Connection.validateOutgoingSubscribe;
        pub const prepareQueue = Connection.ensurePendingPacketQueueAvailable;
        pub const reserve = OutgoingIdentifiers.reserve;
        pub const writePacket = Connection.writeGeneratedPacket;
        pub const writePacketWithDeadline = Connection.writeGeneratedPacketWithDeadline;
        pub const completeSubscribe = ControlCompletion.suback;
        pub const completeUnsubscribe = ControlCompletion.unsuback;
    });

    const ControlCompletion = @import("acknowledgement/control/mod.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const PacketType = OwnedPacket;
        pub const ErrorType = Error;
        pub const canReadBuffered = termination.canReadBuffered;
        pub const observeRetainedDisconnect = Connection.observeRetainedDisconnect;
        pub const observeDisconnect = Connection.observeDisconnectPacket;
        pub const observeQueuedDisconnect = Connection.observeQueuedDisconnect;
        pub const SubAckType = OwnedSubAck;
        pub const UnsubAckType = OwnedUnsubAck;
        pub const readPacket = Connection.readTransportPacket;
        pub const readPacketWithDeadline = Connection.readTransportPacketWithDeadline;
        pub const prepareQueue = Connection.ensurePendingPacketQueueAvailable;
        pub const prepareStorage = Connection.ensurePendingPacketStorage;
        pub const queuePacket = Connection.queuePendingPacket;
        pub const parseSubAck = Connection.parseReadSubAck;
        pub const parseUnsubAck = Connection.parseReadUnsubAck;
    });

    const ControlApi = @import("acknowledgement/control/api.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const SubAckType = OwnedSubAck;
        pub const UnsubAckType = OwnedUnsubAck;
        pub const SubscribeOptionsType = SubscribeOptions;
        pub const UnsubscribeOptionsType = UnsubscribeOptions;
        pub const writeSubscribe = ControlExchange.writeSubscribe;
        pub const writeUnsubscribe = ControlExchange.writeUnsubscribe;
        pub const completeSubscribe = ControlCompletion.suback;
        pub const completeUnsubscribe = ControlCompletion.unsuback;
    });

    pub const writeSubscribe = ControlApi.writeSubscribe;
    pub const writeSubscribeWithTimeout = ControlApi.writeSubscribeWithTimeout;
    pub const writeSubscribeWithDeadline = ControlApi.writeSubscribeWithDeadline;
    pub const completeSubscribe = ControlApi.completeSubscribe;
    pub const completeSubscribeWithTimeout = ControlApi.completeSubscribeWithTimeout;
    pub const completeSubscribeWithDeadline = ControlApi.completeSubscribeWithDeadline;
    pub const writeUnsubscribe = ControlApi.writeUnsubscribe;
    pub const writeUnsubscribeWithTimeout = ControlApi.writeUnsubscribeWithTimeout;
    pub const writeUnsubscribeWithDeadline = ControlApi.writeUnsubscribeWithDeadline;
    pub const completeUnsubscribe = ControlApi.completeUnsubscribe;
    pub const completeUnsubscribeWithTimeout = ControlApi.completeUnsubscribeWithTimeout;
    pub const completeUnsubscribeWithDeadline = ControlApi.completeUnsubscribeWithDeadline;

    pub fn clearPendingPacketState(self: *Connection) void {
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
        if (self.retained_receive.packet()) |packet| {
            if (packet.fixed.packet_type != .disconnect) return self.retained_receive.take();
        }
        const pending = self.pending_packets orelse return null;
        return pending.pop();
    }

    fn validateReadPacketUntil(self: *Connection, packet: *const OwnedPacket, deadline: ?std.Io.Clock.Timestamp) Error!void {
        // Validate wire syntax before semantic direction/state so a packet
        // that is wrong in both ways is still classified as Malformed Packet.
        try mqtt.validatePacketFlags(self.protocol, packet.fixed);
        try self.validateIncomingPacketType(packet.fixed.packet_type);
        self.authentication.ensurePacketAllowed(
            packet.fixed.packet_type,
        ) catch |err| {
            if (err == error.AuthenticationInProgress) {
                self.sendAuthenticationProtocolErrorUntil(deadline);
            }
            return err;
        };
    }

    pub fn finishReadPacket(
        self: *Connection,
        packet_value: OwnedPacket,
    ) Error!OwnedPacket {
        return self.finishReadPacketUntil(packet_value, null);
    }

    fn finishReadPacketUntil(self: *Connection, packet_value: OwnedPacket, deadline: ?std.Io.Clock.Timestamp) Error!OwnedPacket {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        try self.validateReadPacketUntil(&packet, deadline);
        return packet;
    }

    pub fn validateOutgoingPacketType(
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

    pub fn validateIncomingPacketType(
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

    fn sendAuthenticationProtocolErrorUntil(self: *Connection, deadline: ?std.Io.Clock.Timestamp) void {
        // Diagnostic output is secondary to the peer error. Even a pre-wire
        // timeout/size rejection must retire this invalid authentication state.
        defer self.transport_unusable.store(true, .release);
        if (self.protocol != .v5) return;
        if (deadline) |absolute|
            self.writeDisconnectWithDeadline(0x82, &.{}, absolute) catch {}
        else
            self.writeDisconnectWithProperties(0x82, &.{}) catch {};
    }

    fn readAck(self: *Connection, packet_type: mqtt.PacketType) Error!OwnedAck {
        const packet = try TypedReceive.read(self, packet_type, null);
        return self.finishReadAck(packet);
    }

    fn finishReadAck(self: *Connection, packet_value: OwnedPacket) Error!OwnedAck {
        var packet = packet_value;
        errdefer packet.deinit(self.allocator);
        return self.parseReadAck(packet);
    }

    /// Parse borrowed packet storage; the caller retains it on failure.
    fn parseReadAck(self: *Connection, packet: OwnedPacket) Error!OwnedAck {
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

    const OutgoingIdentifiers = @import("packet_identifiers/reservation.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
    });

    pub fn reserveOutgoingPublish(self: *Connection, qos: mqtt.QoS) Error!u16 {
        if (self.outgoing_inflight >= self.max_outgoing_inflight) return error.InflightFull;

        const stage: packet_identifiers.State.Stage = switch (qos) {
            .at_most_once => unreachable,
            .at_least_once => .outgoing_qos1,
            .exactly_once => .outgoing_qos2,
        };
        const packet_id = try OutgoingIdentifiers.reserve(self, stage, null);
        self.outgoing_inflight += 1;
        return packet_id;
    }

    fn releaseOutgoingPublish(self: *Connection, packet_id: u16, qos: mqtt.QoS) void {
        const stage: packet_identifiers.State.Stage = switch (qos) {
            .at_most_once => return,
            .at_least_once => .outgoing_qos1,
            .exactly_once => .outgoing_qos2,
        };
        if (qos == .exactly_once and self.packet_identifiers.remove(
            self.allocator,
            packet_id,
            .outgoing_qos2_pubrel,
        )) {} else if (!self.packet_identifiers.remove(self.allocator, packet_id, stage)) return;
        self.outgoing_inflight -= 1;
    }
};

const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || quic.tls_client_hello.Error || quic.tls.auth.Error || quic.one_rtt.Error || quic.zero_rtt.handshake.Error || quic.zero_rtt.replay_filter.Error || quic.resumption.tls_psk.Error || quic.resumption.ticket.handshake.Error || quic.Error || std.Io.RandomSecureError || std.Io.Writer.Error || error{
    InvalidHandshakeFlight,
    MissingCryptoFrame,
    MissingAlpn,
};

pub const ClientOptions = struct {
    /// Destination Connection ID from the client's first Initial.  It seeds the
    /// first Initial secrets and remains the value expected in the server's
    /// original_destination_connection_id transport parameter after Retry.
    original_destination_connection_id: []const u8,
    local_connection_id: []const u8,
    /// Retry Source Connection ID accepted from a validated Retry packet.  When
    /// set, the retried Initial uses this value as its Destination Connection
    /// ID and key-derivation input while preserving the original DCID above for
    /// transport-parameter validation.
    retry_source_connection_id: []const u8 = &.{},
    version: quic.Version = .version_1,
    /// Versions this client is willing to retry with if the server answers the
    /// first Initial with Version Negotiation.  Preference order is preserved.
    available_versions: []const quic.Version = &.{ .version_1, .version_2 },
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &.{"h3"},
    /// Optional raw override for callers that need full control over the TLS
    /// QUIC transport-parameter extension.  When empty, netz emits
    /// `local_transport_parameters` plus the required connection-id parameter.
    transport_parameters: []const u8 = &.{},
    local_transport_parameters: quic.TransportParameters = quic.practical_transport_parameters,
    address_validation_token: []const u8 = &.{},
    max_crypto_buffer: usize = 4096,
    max_crypto_frame_data_len: usize = 1024,
    client_initial_packet_number: u64 = 0,
    client_handshake_packet_number: u64 = 0,
    initial_one_rtt_config: OneRttConfig = .{},
    random: ?[32]u8 = null,
    x25519_secret_key: ?[32]u8 = null,
    keylog: ?*quic.keylog.Log = null,
    resumption_session: ?*const quic.resumption.Session = null,
    resumption_now_ms: ?u64 = null,
    resumption_server_id: ?[]const u8 = null,
    auto_resumption: ?quic.resumption.ticket.handshake.ClientAutoResume = null,
    early_data: ?quic.zero_rtt.handshake.ClientOffer = null,
    server_auth: ?quic.tls.auth.ClientVerifier = null,
};

pub const ServerPsk = struct {
    identity: []const u8,
    secret: [32]u8,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    now_ms: u64,
    age_tolerance_ms: u32 = 10_000,
};

pub const ServerEarlyDataPolicy = struct {
    accept: bool = false,
    replay_filter: *quic.zero_rtt.ReplayFilter,
    /// Stable application request identity (for example method+origin+request
    /// nonce), not merely the replayable ticket identity itself.
    replay_key: []const u8 = &.{},
};

pub const ServerOptions = struct {
    local_connection_id: []const u8,
    alpn_protocol: []const u8 = "h3",
    /// Optional raw override for the server transport-parameter extension.
    /// When empty, netz emits practical defaults together with server
    /// connection-id parameters derived from the received Initial packet.
    transport_parameters: []const u8 = &.{},
    local_transport_parameters: quic.TransportParameters = quic.practical_transport_parameters,
    address_validation_secrets: []const quic.address_validation_token.Secret = &.{},
    address_validation_peer: []const u8 = &.{},
    address_validation_now_ns: i64 = 0,
    /// Retry metadata from the first Initial/Retry exchange.  When set, accept()
    /// validates the Initial token as a Retry token bound to ODCID+RSCID and
    /// advertises both `original_destination_connection_id` and
    /// `retry_source_connection_id` transport parameters.
    retry_original_destination_connection_id: []const u8 = &.{},
    retry_source_connection_id: []const u8 = &.{},
    version: quic.Version = .version_1,
    /// Versions this server advertises in RFC 9368 version_information.  If the
    /// server sends Version Negotiation, keep this aligned with that response so
    /// clients can authenticate that the selected version was not downgraded.
    available_versions: []const quic.Version = &.{ .version_1, .version_2 },
    max_crypto_buffer: usize = 4096,
    max_crypto_frame_data_len: usize = 1024,
    server_initial_packet_number: u64 = 0,
    server_handshake_packet_number: u64 = 0,
    initial_one_rtt_config: OneRttConfig = .{},
    random: ?[32]u8 = null,
    x25519_secret_key: ?[32]u8 = null,
    keylog: ?*quic.keylog.Log = null,
    psk: ?ServerPsk = null,
    auto_resumption: ?quic.resumption.ticket.handshake.ServerAutoResume = null,
    early_data: ?ServerEarlyDataPolicy = null,
    identity: ?quic.tls.auth.ServerIdentity = null,
};

pub const OneRttConfig = struct {
    max_ack_ranges: usize = 64,
    max_frames_per_packet: usize = 16,
    /// Legacy direct 1-RTT flow-control knobs are retained for source
    /// compatibility, but integrated handshakes now derive the actual send and
    /// receive limits from negotiated transport parameters.  Set
    /// ClientOptions/ServerOptions.local_transport_parameters when controlling
    /// handshake-established flow credit.
    initial_send_max_data: u64 = std.math.maxInt(u62),
    initial_receive_max_data: u64 = std.math.maxInt(u62),
    receive_window: u64 = 64 * 1024,
    initial_send_max_stream_data: u64 = std.math.maxInt(u62),
    initial_receive_max_stream_data: u64 = std.math.maxInt(u62),
    stream_receive_window: u64 = 64 * 1024,
    max_datagram_size: usize = quic.congestion.default_max_datagram_size,
    congestion_algorithm: quic.congestion.Algorithm = .cubic,
    enable_hystart: bool = true,
    enable_pacing: bool = true,
    pacing_max_burst_packets: usize = quic.pacing.Pacer.default_max_burst_packets,

    fn apply(
        self: OneRttConfig,
        peer: net.IpAddress,
        receive_keys: quic.protection.PacketProtectionKeys,
        send_keys: quic.protection.PacketProtectionKeys,
        local_connection_id: []const u8,
        peer_connection_id: []const u8,
        local_endpoint: quic.one_rtt.ConnectionConfig.EndpointRole,
        local_transport_parameters: quic.TransportParameters,
        peer_transport_parameters: quic.TransportParameters,
    ) quic.one_rtt.ConnectionConfig {
        return .{
            .peer = peer,
            .receive_keys = receive_keys,
            .send_keys = send_keys,
            .local_connection_id = local_connection_id,
            .peer_connection_id = peer_connection_id,
            .local_endpoint = local_endpoint,
            .max_ack_ranges = self.max_ack_ranges,
            .max_frames_per_packet = self.max_frames_per_packet,
            .initial_send_max_data = @min(self.initial_send_max_data, peer_transport_parameters.initial_max_data),
            .initial_receive_max_data = @min(self.initial_receive_max_data, local_transport_parameters.initial_max_data),
            .receive_window = self.receive_window,
            .initial_send_max_stream_data = self.initial_send_max_stream_data,
            .initial_receive_max_stream_data = self.initial_receive_max_stream_data,
            .initial_send_max_stream_data_bidi_local = @min(self.initial_send_max_stream_data, peer_transport_parameters.initial_max_stream_data_bidi_local),
            .initial_send_max_stream_data_bidi_remote = @min(self.initial_send_max_stream_data, peer_transport_parameters.initial_max_stream_data_bidi_remote),
            .initial_send_max_stream_data_uni = @min(self.initial_send_max_stream_data, peer_transport_parameters.initial_max_stream_data_uni),
            .initial_receive_max_stream_data_bidi_local = @min(self.initial_receive_max_stream_data, local_transport_parameters.initial_max_stream_data_bidi_local),
            .initial_receive_max_stream_data_bidi_remote = @min(self.initial_receive_max_stream_data, local_transport_parameters.initial_max_stream_data_bidi_remote),
            .initial_receive_max_stream_data_uni = @min(self.initial_receive_max_stream_data, local_transport_parameters.initial_max_stream_data_uni),
            .initial_send_max_streams_bidi = peer_transport_parameters.initial_max_streams_bidi,
            .initial_send_max_streams_uni = peer_transport_parameters.initial_max_streams_uni,
            .initial_receive_max_streams_bidi = local_transport_parameters.initial_max_streams_bidi,
            .initial_receive_max_streams_uni = local_transport_parameters.initial_max_streams_uni,
            .stream_receive_window = self.stream_receive_window,
            .max_datagram_size = @min(
                self.max_datagram_size,
                std.math.cast(usize, peer_transport_parameters.max_udp_payload_size) orelse std.math.maxInt(usize),
            ),
            .congestion_algorithm = self.congestion_algorithm,
            .enable_hystart = self.enable_hystart,
            .enable_pacing = self.enable_pacing,
            .pacing_max_burst_packets = self.pacing_max_burst_packets,
            .active_connection_id_limit = std.math.cast(usize, local_transport_parameters.active_connection_id_limit) orelse std.math.maxInt(usize),
            .peer_active_connection_id_limit = std.math.cast(usize, peer_transport_parameters.active_connection_id_limit) orelse std.math.maxInt(usize),
            .local_max_idle_timeout_ms = local_transport_parameters.max_idle_timeout,
            .peer_max_idle_timeout_ms = peer_transport_parameters.max_idle_timeout,
            .local_ack_delay_exponent = local_transport_parameters.ack_delay_exponent,
            .peer_ack_delay_exponent = peer_transport_parameters.ack_delay_exponent,
            .peer_max_ack_delay_ms = peer_transport_parameters.max_ack_delay,
            .peer_disable_active_migration = peer_transport_parameters.disable_active_migration,
            .peer_preferred_address = peer_transport_parameters.preferred_address,
            .local_max_datagram_frame_size = if (local_transport_parameters.max_datagram_frame_size) |size| std.math.cast(usize, size) orelse std.math.maxInt(usize) else null,
            .peer_max_datagram_frame_size = if (peer_transport_parameters.max_datagram_frame_size) |size| std.math.cast(usize, size) orelse std.math.maxInt(usize) else null,
            .enable_ack_frequency = local_transport_parameters.min_ack_delay != null or peer_transport_parameters.min_ack_delay != null,
            .local_min_ack_delay = local_transport_parameters.min_ack_delay,
            .peer_min_ack_delay = peer_transport_parameters.min_ack_delay,
        };
    }
};

pub const EstablishedConnection = struct {
    connection: quic.one_rtt.Connection,
    local_connection_id: []u8,
    peer_connection_id: []u8,
    alpn: []u8,
    resumed: bool = false,
    early_data_status: quic.zero_rtt.handshake.Status = .not_offered,
    resumption_master_secret: [32]u8,
    peer_transport_parameters: quic.resumption.Snapshot,
    post_handshake_send_crypto_offset: u64 = 0,
    post_handshake_receive_crypto_offset: u64 = 0,

    /// Issue one post-handshake TLS 1.3 ticket and register it in the bounded
    /// server store before sending it in 1-RTT CRYPTO.
    pub fn issueSessionTicket(
        self: *EstablishedConnection,
        io: std.Io,
        config: quic.resumption.ticket.handshake.ServerConfig,
    ) Error!quic.resumption.ticket.handshake.Issued {
        return quic.resumption.ticket.handshake.issue(
            &self.connection,
            io,
            config,
            self.resumption_master_secret,
            &self.post_handshake_send_crypto_offset,
        );
    }

    /// Receive one post-handshake NewSessionTicket and atomically insert an
    /// origin+ALPN-bound owned session into the client's cache.
    pub fn receiveAndCacheSessionTicket(
        self: *EstablishedConnection,
        config: quic.resumption.ticket.handshake.ClientConfig,
    ) Error!void {
        try quic.resumption.ticket.handshake.receiveAndCache(
            &self.connection,
            config,
            self.resumption_master_secret,
            self.alpn,
            self.peer_transport_parameters,
            &self.post_handshake_receive_crypto_offset,
        );
    }

    pub fn deinit(self: *EstablishedConnection) void {
        const allocator = self.connection.endpoint.allocator;
        self.connection.deinit();
        allocator.free(self.local_connection_id);
        allocator.free(self.peer_connection_id);
        allocator.free(self.alpn);
        self.* = undefined;
    }
};

fn validateConfiguredVersions(version: quic.Version, available_versions: []const quic.Version) Error!void {
    if (version == .negotiation or quic.isReservedVersionWire(version.wireValue())) return error.InvalidVersionNegotiation;
    if (available_versions.len == 0) return error.InvalidVersionNegotiation;
    var contains_chosen = false;
    for (available_versions) |available| {
        if (available == .negotiation) return error.InvalidVersionNegotiation;
        if (available.wireValue() == version.wireValue()) contains_chosen = true;
    }
    if (!contains_chosen) return error.InvalidVersionNegotiation;
}

fn clientInitialDestinationConnectionId(options: ClientOptions) []const u8 {
    if (options.retry_source_connection_id.len != 0) return options.retry_source_connection_id;
    return options.original_destination_connection_id;
}

fn isVersionNegotiationDatagram(bytes: []const u8) bool {
    if (bytes.len < 5 or (bytes[0] & 0x80) == 0) return false;
    return std.mem.readInt(u32, bytes[1..5], .big) == quic.Version.negotiation.wireValue();
}

pub fn connect(endpoint: *quic.runtime.Endpoint, peer: net.IpAddress, options: ClientOptions) Error!EstablishedConnection {
    if (options.resumption_session == null and
        options.early_data == null and
        options.auto_resumption != null)
    {
        const automatic = options.auto_resumption.?;
        var session = (try quic.resumption.ticket.handshake.acquireFirst(
            automatic,
            options.alpn_protocols,
        )) orelse return connectAttempt(endpoint, peer, options, false);
        defer session.deinit();
        var resumed_options = options;
        resumed_options.resumption_session = &session;
        resumed_options.resumption_now_ms = automatic.now_ms;
        resumed_options.resumption_server_id = automatic.server_id;
        return connectAttempt(endpoint, peer, resumed_options, false);
    }
    return connectAttempt(endpoint, peer, options, false);
}

fn connectAttempt(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    options: ClientOptions,
    version_negotiation_processed: bool,
) Error!EstablishedConnection {
    try validateConfiguredVersions(options.version, options.available_versions);
    if (options.retry_source_connection_id.len != 0 and options.address_validation_token.len == 0) {
        return error.InvalidPacket;
    }

    const client_secret = try secretKey(endpoint.io, options.x25519_secret_key);
    const client_public = try quic.tls_client_hello.x25519PublicKey(client_secret);
    const client_random = try random32(endpoint.io, options.random);
    const initial_destination_connection_id = clientInitialDestinationConnectionId(options);
    const initial_secrets = try quic.protection.deriveInitialSecretsForVersion(options.version.wireValue(), initial_destination_connection_id);

    var local_transport_parameters = options.local_transport_parameters;
    var encoded_transport_parameters: std.ArrayList(u8) = .empty;
    defer encoded_transport_parameters.deinit(endpoint.allocator);
    const transport_parameters = try clientTransportParameters(
        endpoint.allocator,
        options,
        &local_transport_parameters,
        &encoded_transport_parameters,
    );

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, endpoint.allocator, .{
        .random = client_random,
        .x25519_public_key = client_public,
        .server_name = options.server_name,
        .alpn_protocols = options.alpn_protocols,
        .transport_parameters = transport_parameters,
    });
    const resumption_session = if (options.early_data) |early_data|
        &early_data.lease.session
    else
        options.resumption_session;
    const offer_early_data = options.early_data != null;
    if (offer_early_data and options.retry_source_connection_id.len != 0) {
        // RFC 9001 §4.6: a client MUST NOT send 0-RTT after Retry because the
        // original early-data keys are bound to the pre-Retry ClientHello.
        return error.EarlyDataIncompatibleWithRetry;
    }
    if (options.early_data) |early_data| {
        try early_data.validate();
        if (options.resumption_session) |explicit_session| {
            if (!std.mem.eql(
                u8,
                &early_data.lease.session.psk,
                &explicit_session.psk,
            ) or
                !std.mem.eql(
                    u8,
                    early_data.lease.session.ticket,
                    explicit_session.ticket,
                ))
            {
                return error.InvalidEarlyDataLease;
            }
        }
    }
    if (resumption_session) |session| {
        const now_ms = options.resumption_now_ms orelse
            return error.InvalidClientHello;
        if (now_ms < session.issued_at_ms) return error.InvalidClientHello;
        const expected_server_id = options.resumption_server_id orelse
            return error.InvalidClientHello;
        if (!std.mem.eql(u8, session.server_id, expected_server_id)) {
            return error.InvalidClientHello;
        }
        var offered_alpn = false;
        for (options.alpn_protocols) |protocol| {
            if (std.mem.eql(u8, protocol, session.alpn)) {
                offered_alpn = true;
                break;
            }
        }
        if (!offered_alpn) return error.InvalidClientHello;
        const age = now_ms - session.issued_at_ms;
        if (age > @as(u64, session.lifetime_seconds) * std.time.ms_per_s or
            age > std.math.maxInt(u32))
        {
            return error.ExpiredPsk;
        }
        try quic.resumption.tls_psk.appendClientOfferWithEarlyData(
            &client_hello,
            endpoint.allocator,
            session.ticket,
            session.obfuscatedTicketAge(now_ms),
            session.psk,
            offer_early_data,
        );
    }

    if (options.early_data) |early_data| {
        const keys = try quic.zero_rtt.handshake.clientKeysForVersion(
            options.version.wireValue(),
            early_data.lease.session.psk,
            client_hello.items,
        );
        try quic.initial_exchange.sendCoalescedInitialZeroRtt(
            endpoint,
            peer,
            initial_secrets.client,
            .{
                .version = options.version.wireValue(),
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = options.local_connection_id,
                .token = options.address_validation_token,
                .packet_number = options.client_initial_packet_number,
                .crypto_data = client_hello.items,
                .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
                .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
            },
            keys.packet,
            .{
                .version = options.version.wireValue(),
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = options.local_connection_id,
                .packet_number = 0,
                .packet_number_len = early_data.packet_number_len,
                .frames = early_data.frames,
            },
        );
        early_data.cache.consumeEarlyData(early_data.lease) catch unreachable;
    } else {
        try quic.initial_exchange.sendInitialCrypto(endpoint, peer, initial_secrets.client, .{
            .version = options.version.wireValue(),
            .destination_connection_id = initial_destination_connection_id,
            .source_connection_id = options.local_connection_id,
            .token = options.address_validation_token,
            .packet_number = options.client_initial_packet_number,
            .crypto_data = client_hello.items,
            .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
            .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
        });
    }

    var server_datagram = try endpoint.receiveBytes();
    defer server_datagram.deinit(endpoint.allocator);
    if (isVersionNegotiationDatagram(server_datagram.bytes)) {
        var negotiated = (try quic.version_negotiation.processClient(endpoint.allocator, .{
            .chosen_version = options.version,
            .available_versions = options.available_versions,
            .original_destination_connection_id = options.original_destination_connection_id,
            .initial_source_connection_id = options.local_connection_id,
            .initial_sent = true,
            .retry_processed = options.retry_source_connection_id.len != 0,
            .version_negotiation_processed = version_negotiation_processed,
        }, server_datagram.bytes)) orelse return error.InvalidHandshakeFlight;
        defer negotiated.deinit(endpoint.allocator);
        var next = negotiated.clientOptions(options);
        // 0-RTT keys are version-specific and the lease was consumed once its
        // first packet left the socket. Continue with ordinary PSK resumption
        // rather than replaying early data under the negotiated version.
        next.early_data = null;
        next.resumption_session = resumption_session;
        return connectAttempt(endpoint, peer, next, true);
    }

    const server_initial_info = try quic.protection.peekProtectedLongPacketInfo(server_datagram.bytes);
    if (server_initial_info.packet_type != .initial) return error.InvalidHandshakeFlight;

    var server_initial = try quic.initial_exchange.openInitialCrypto(
        endpoint,
        server_datagram.from,
        server_datagram.bytes[0..server_initial_info.len],
        initial_secrets.server,
        0,
        options.max_crypto_buffer,
    );
    defer server_initial.deinit(endpoint.allocator);
    const parsed_server = try quic.tls_client_hello.parseServerHello(server_initial.crypto_data);
    const offered_psk = resumption_session != null;
    if (parsed_server.selected_psk and !offered_psk) return error.InvalidServerHello;
    const selected_psk: ?[32]u8 = if (parsed_server.selected_psk)
        resumption_session.?.psk
    else
        null;
    const shared = try quic.tls_client_hello.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const hs_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data });
    const handshake = try quic.tls_client_hello.deriveHandshakeSecretsWithPskForVersion(
        options.version.wireValue(),
        shared,
        hs_hash,
        selected_psk,
    );
    if (options.keylog) |keylog| {
        try keylog.writeHandshakeSecrets(
            client_random,
            handshake.client_handshake_traffic_secret,
            handshake.server_handshake_traffic_secret,
        );
    }

    var server_handshake = try receiveServerHandshakeCrypto(
        endpoint,
        server_initial.from,
        server_datagram.bytes[server_initial_info.len..],
        handshake.server_quic,
        0,
        options.max_crypto_buffer,
    );
    defer server_handshake.deinit(endpoint.allocator);
    const server_flight = try splitServerFlight(
        server_handshake.crypto_data,
        parsed_server.selected_psk or options.server_auth == null,
    );
    const encrypted_extensions = try quic.tls_client_hello.parseEncryptedExtensions(server_flight.encrypted_extensions);
    try ensureOfferedAlpn(options.alpn_protocols, encrypted_extensions.alpn);
    const peer_transport_parameters = try quic.parseTransportParametersTyped(
        endpoint.allocator,
        encrypted_extensions.transport_parameters,
        .server,
    );
    try validateServerTransportParameters(
        peer_transport_parameters,
        server_initial.packet.source_connection_id,
        options.original_destination_connection_id,
        options.retry_source_connection_id,
        options.version,
        options.available_versions,
        version_negotiation_processed,
    );
    const early_data_status = try quic.zero_rtt.handshake.validateClientAcceptance(
        offer_early_data,
        parsed_server.selected_psk,
        encrypted_extensions.early_data_accepted,
        if (options.early_data) |early_data|
            early_data.lease.session.transport_parameters
        else
            quic.resumption.Snapshot.fromTransportParameters(.{}),
        peer_transport_parameters,
    );
    if (parsed_server.selected_psk) {
        if (server_flight.certificate != null or
            server_flight.certificate_verify != null)
        {
            return error.InvalidHandshakeFlight;
        }
    } else if (options.server_auth) |verifier| {
        const certificate_bytes = server_flight.certificate orelse
            return error.InvalidHandshakeFlight;
        const certificate_verify_bytes =
            server_flight.certificate_verify orelse
            return error.InvalidHandshakeFlight;
        var certificate = try quic.tls.auth.parseCertificate(
            endpoint.allocator,
            certificate_bytes,
        );
        defer certificate.deinit(endpoint.allocator);
        try verifier.verifyTrust(options.server_name, certificate.entries);
        const certificate_verify =
            try quic.tls.auth.parseCertificateVerify(
                certificate_verify_bytes,
            );
        try quic.tls.auth.verifyCertificateVerify(
            certificate.entries[0],
            certificate_verify,
            hashParts(&.{
                client_hello.items,
                server_initial.crypto_data,
                server_flight.encrypted_extensions,
                certificate_bytes,
            }),
        );
    } else if (server_flight.certificate != null or
        server_flight.certificate_verify != null)
    {
        return error.InvalidHandshakeFlight;
    }
    const server_finished = try quic.tls_client_hello.parseFinished(server_flight.finished);
    const server_finished_hash = hashServerFlightBeforeFinished(
        client_hello.items,
        server_initial.crypto_data,
        server_flight,
    );
    try quic.tls_client_hello.verifyFinished(handshake.server_handshake_traffic_secret, server_finished_hash, server_finished);
    const application_transcript_hash = hashParts(&.{
        client_hello.items,
        server_initial.crypto_data,
        server_flight.before_finished,
        server_flight.finished,
    });
    const application = try quic.tls_client_hello.deriveApplicationSecretsForVersion(
        options.version.wireValue(),
        handshake.handshake_secret,
        application_transcript_hash,
    );

    const client_verify = quic.tls_client_hello.computeFinishedVerifyData(
        handshake.client_handshake_traffic_secret,
        application_transcript_hash,
    );
    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeFinished(&client_finished, endpoint.allocator, client_verify);

    try quic.initial_exchange.sendHandshakeCrypto(endpoint, server_initial.from, handshake.client_quic, .{
        .version = options.version.wireValue(),
        .destination_connection_id = server_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.client_handshake_packet_number,
        .crypto_data = client_finished.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
    });

    if (options.keylog) |keylog| {
        try keylog.writeApplicationSecrets(
            client_random,
            application.client_application_traffic_secret,
            application.server_application_traffic_secret,
        );
    }
    var established = try establishedConnection(
        endpoint,
        server_initial.from,
        application.server_quic,
        application.client_quic,
        options.local_connection_id,
        server_initial.packet.source_connection_id,
        options.initial_one_rtt_config,
        .client,
        local_transport_parameters,
        peer_transport_parameters,
        encrypted_extensions.alpn,
        parsed_server.selected_psk,
        early_data_status,
        quic.resumption.ticket.codec.deriveResumptionMasterSecret(
            application.master_secret,
            hashParts(&.{
                client_hello.items,
                server_initial.crypto_data,
                server_flight.before_finished,
                server_flight.finished,
                client_finished.items,
            }),
        ),
    );
    errdefer established.deinit();
    if (options.early_data) |early_data| {
        try established.connection.importSentEarlyData(
            0,
            early_data.frames,
        );
    }
    return established;
}

pub fn accept(endpoint: *quic.runtime.Endpoint, options: ServerOptions) Error!EstablishedConnection {
    try validateConfiguredVersions(options.version, options.available_versions);
    if (options.psk) |psk| {
        if (psk.identity.len == 0 or psk.lifetime_seconds == 0) {
            return error.InvalidClientHello;
        }
    }
    if ((options.retry_original_destination_connection_id.len == 0) != (options.retry_source_connection_id.len == 0)) {
        return error.InvalidPacket;
    }

    var client_initial = try receiveClientInitial(endpoint, 0, options.max_crypto_buffer, options.retry_source_connection_id, options.version);
    defer client_initial.deinit(endpoint.allocator);
    const original_destination_connection_id = serverOriginalDestinationConnectionId(
        client_initial.packet.destination_connection_id,
        options,
    );
    try validateAddressTokenForInitial(endpoint.allocator, client_initial.packet.token, original_destination_connection_id, options);

    var parsed_client = try quic.tls_client_hello.parseClientHello(endpoint.allocator, client_initial.crypto_data);
    defer parsed_client.deinit(endpoint.allocator);
    var automatic_psk_lease: ?quic.resumption.ticket.store.Lease = null;
    defer if (automatic_psk_lease) |*lease| lease.deinit();
    var effective_psk = options.psk;
    if (effective_psk == null) {
        if (options.auto_resumption) |automatic| {
            if (parsed_client.psk_offer) |offer| {
                automatic_psk_lease = try quic.resumption.ticket.handshake.lookupServer(
                    automatic,
                    offer.identity,
                );
                if (automatic_psk_lease) |*lease| {
                    effective_psk = .{
                        .identity = lease.identity,
                        .secret = lease.secret,
                        .age_add = lease.age_add,
                        .issued_at_ms = lease.issued_at_ms,
                        .lifetime_seconds = lease.lifetime_seconds,
                        .now_ms = automatic.now_ms,
                        .age_tolerance_ms = automatic.age_tolerance_ms,
                    };
                }
            }
        }
    }
    const alpn = try chooseAlpn(options.alpn_protocol, parsed_client.alpn_protocols);
    if (effective_psk == null) {
        if (options.identity) |identity| {
            const supported = switch (identity.signer.scheme()) {
                quic.tls.auth.signature_scheme_ed25519 => parsed_client.supports_ed25519,
                quic.tls.auth.signature_scheme_ecdsa_secp256r1_sha256 => parsed_client.supports_ecdsa_p256_sha256,
                else => false,
            };
            if (!supported) return error.UnsupportedSignatureScheme;
        }
    }
    const peer_transport_parameters = try quic.parseTransportParametersTyped(
        endpoint.allocator,
        parsed_client.transport_parameters,
        .client,
    );
    try validateClientTransportParameters(
        peer_transport_parameters,
        client_initial.packet.source_connection_id,
        options.version,
        options.available_versions,
    );

    const server_secret = try secretKey(endpoint.io, options.x25519_secret_key);
    const server_public = try quic.tls_client_hello.x25519PublicKey(server_secret);
    const server_random = try random32(endpoint.io, options.random);
    const shared = try quic.tls_client_hello.x25519SharedSecret(server_secret, parsed_client.x25519_public_key);
    var selected_psk: ?[32]u8 = null;
    var early_data_accepted = false;
    var early_data_keys: ?quic.zero_rtt.handshake.ClientKeys = null;
    const client_offered_early_data =
        try quic.resumption.tls_psk.clientOfferedEarlyData(
            client_initial.crypto_data,
        );
    if (client_offered_early_data and parsed_client.psk_offer == null) {
        return error.UnexpectedEarlyData;
    }
    if (parsed_client.psk_offer) |offer| {
        if (effective_psk) |configured_psk| {
            if (std.mem.eql(u8, offer.identity, configured_psk.identity)) {
                try quic.resumption.tls_psk.verifyClientOffer(
                    client_initial.crypto_data,
                    offer,
                    configured_psk.identity,
                    configured_psk.secret,
                );
                try quic.resumption.tls_psk.validateTicketAge(offer, .{
                    .age_add = configured_psk.age_add,
                    .issued_at_ms = configured_psk.issued_at_ms,
                    .lifetime_seconds = configured_psk.lifetime_seconds,
                    .now_ms = configured_psk.now_ms,
                    .tolerance_ms = configured_psk.age_tolerance_ms,
                });
                selected_psk = configured_psk.secret;
                const early_data_policy = options.early_data;
                if (client_offered_early_data and
                    early_data_policy != null and
                    early_data_policy.?.accept)
                {
                    const replay = early_data_policy.?;
                    const lifetime_ms =
                        @as(u64, configured_psk.lifetime_seconds) *
                        std.time.ms_per_s;
                    const expires_at_ms = std.math.add(
                        u64,
                        configured_psk.issued_at_ms,
                        lifetime_ms,
                    ) catch return error.ExpiredPsk;
                    try replay.replay_filter.checkAndMark(
                        replay.replay_key,
                        configured_psk.now_ms,
                        expires_at_ms,
                    );
                    early_data_keys =
                        try quic.zero_rtt.handshake.clientKeysForVersion(
                            options.version.wireValue(),
                            configured_psk.secret,
                            client_initial.crypto_data,
                        );
                    early_data_accepted = true;
                }
            }
        }
    }
    var pending_early_data: ?quic.zero_rtt.Packet = null;
    defer if (pending_early_data) |*early_data| {
        early_data.deinit(endpoint.allocator);
    };
    if (early_data_accepted) {
        pending_early_data = try openClientEarlyData(
            endpoint,
            client_initial.from,
            client_initial.coalesced_tail,
            early_data_keys.?.packet,
            0,
            options.initial_one_rtt_config.max_frames_per_packet,
            client_initial.packet.destination_connection_id,
            client_initial.packet.source_connection_id,
        );
    } else if (client_initial.coalesced_tail.len != 0) {
        try validateRejectedEarlyDataTail(client_initial.coalesced_tail);
    }

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeServerHello(&server_hello, endpoint.allocator, .{
        .random = server_random,
        .x25519_public_key = server_public,
        .select_psk = selected_psk != null,
    });
    const hs_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items });
    const handshake = try quic.tls_client_hello.deriveHandshakeSecretsWithPskForVersion(
        options.version.wireValue(),
        shared,
        hs_hash,
        selected_psk,
    );
    if (options.keylog) |keylog| {
        try keylog.writeHandshakeSecrets(
            parsed_client.random,
            handshake.client_handshake_traffic_secret,
            handshake.server_handshake_traffic_secret,
        );
    }

    var local_transport_parameters = options.local_transport_parameters;
    var encoded_transport_parameters: std.ArrayList(u8) = .empty;
    defer encoded_transport_parameters.deinit(endpoint.allocator);
    const transport_parameters = try serverTransportParameters(
        endpoint.allocator,
        options,
        original_destination_connection_id,
        options.retry_source_connection_id,
        &local_transport_parameters,
        &encoded_transport_parameters,
    );

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeEncryptedExtensionsWithEarlyData(
        &encrypted_extensions,
        endpoint.allocator,
        alpn,
        transport_parameters,
        early_data_accepted,
    );
    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(endpoint.allocator);
    try server_flight.appendSlice(endpoint.allocator, encrypted_extensions.items);
    if (selected_psk == null and options.identity != null) {
        const identity = options.identity.?;
        try identity.validate();
        var certificate: std.ArrayList(u8) = .empty;
        defer certificate.deinit(endpoint.allocator);
        try quic.tls.auth.writeCertificate(
            &certificate,
            endpoint.allocator,
            identity.certificate_chain,
        );
        try server_flight.appendSlice(endpoint.allocator, certificate.items);

        var certificate_verify: std.ArrayList(u8) = .empty;
        defer certificate_verify.deinit(endpoint.allocator);
        try quic.tls.auth.writeCertificateVerify(
            &certificate_verify,
            endpoint.allocator,
            identity.signer,
            hashParts(&.{
                client_initial.crypto_data,
                server_hello.items,
                encrypted_extensions.items,
                certificate.items,
            }),
        );
        try server_flight.appendSlice(
            endpoint.allocator,
            certificate_verify.items,
        );
    }
    const server_finished_hash = hashParts(&.{
        client_initial.crypto_data,
        server_hello.items,
        server_flight.items,
    });
    const server_verify = quic.tls_client_hello.computeFinishedVerifyData(
        handshake.server_handshake_traffic_secret,
        server_finished_hash,
    );
    var server_finished: std.ArrayList(u8) = .empty;
    defer server_finished.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeFinished(
        &server_finished,
        endpoint.allocator,
        server_verify,
    );
    try server_flight.appendSlice(endpoint.allocator, server_finished.items);
    try quic.initial_exchange.sendCoalescedInitialHandshakeCrypto(
        endpoint,
        client_initial.from,
        client_initial.initial_secrets.server,
        .{
            .version = options.version.wireValue(),
            .destination_connection_id = client_initial.packet.source_connection_id,
            .source_connection_id = options.local_connection_id,
            .packet_number = options.server_initial_packet_number,
            .crypto_data = server_hello.items,
            .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
            .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
        },
        handshake.server_quic,
        .{
            .version = options.version.wireValue(),
            .destination_connection_id = client_initial.packet.source_connection_id,
            .source_connection_id = options.local_connection_id,
            .packet_number = options.server_handshake_packet_number,
            .crypto_data = server_flight.items,
            .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
        },
    );

    var client_finished = try quic.initial_exchange.receiveHandshakeCrypto(endpoint, handshake.client_quic, 0, options.max_crypto_buffer);
    defer client_finished.deinit(endpoint.allocator);
    const client_verify = try quic.tls_client_hello.parseFinished(client_finished.crypto_data);
    const client_finished_hash = hashParts(&.{
        client_initial.crypto_data,
        server_hello.items,
        server_flight.items,
    });
    try quic.tls_client_hello.verifyFinished(handshake.client_handshake_traffic_secret, client_finished_hash, client_verify);

    const application = try quic.tls_client_hello.deriveApplicationSecretsForVersion(
        options.version.wireValue(),
        handshake.handshake_secret,
        client_finished_hash,
    );
    if (options.keylog) |keylog| {
        try keylog.writeApplicationSecrets(
            parsed_client.random,
            application.client_application_traffic_secret,
            application.server_application_traffic_secret,
        );
    }
    var established = try establishedConnection(
        endpoint,
        client_initial.from,
        application.client_quic,
        application.server_quic,
        options.local_connection_id,
        client_initial.packet.source_connection_id,
        options.initial_one_rtt_config,
        .server,
        local_transport_parameters,
        peer_transport_parameters,
        alpn,
        selected_psk != null,
        if (early_data_accepted) .accepted else if (client_offered_early_data) .rejected else .not_offered,
        quic.resumption.ticket.codec.deriveResumptionMasterSecret(
            application.master_secret,
            hashParts(&.{
                client_initial.crypto_data,
                server_hello.items,
                server_flight.items,
                client_finished.crypto_data,
            }),
        ),
    );
    errdefer established.deinit();
    if (pending_early_data) |*early_data| {
        try established.connection.applyEarlyDataFrames(
            early_data.packet.packet_number,
            early_data.frames,
        );
    }
    return established;
}

fn serverOriginalDestinationConnectionId(received_destination_connection_id: []const u8, options: ServerOptions) []const u8 {
    if (options.retry_original_destination_connection_id.len != 0) return options.retry_original_destination_connection_id;
    return received_destination_connection_id;
}

fn validateAddressTokenForInitial(
    allocator: std.mem.Allocator,
    token: []const u8,
    original_destination_connection_id: []const u8,
    options: ServerOptions,
) Error!void {
    if (token.len == 0) {
        if (options.retry_source_connection_id.len != 0) return error.InvalidPacket;
        return;
    }
    if (options.retry_source_connection_id.len != 0) {
        if (options.retry_original_destination_connection_id.len == 0 or
            options.address_validation_secrets.len == 0 or
            options.address_validation_peer.len == 0) return error.InvalidPacket;
        _ = quic.address_validation_token.validateRetryAnySecret(
            allocator,
            options.address_validation_secrets,
            options.version,
            options.address_validation_now_ns,
            options.address_validation_peer,
            original_destination_connection_id,
            options.retry_source_connection_id,
            token,
        ) catch return error.InvalidPacket;
        return;
    }
    if (options.address_validation_secrets.len == 0 or options.address_validation_peer.len == 0) return;
    _ = quic.address_validation_token.validateAnySecret(
        options.address_validation_secrets,
        .new_token,
        options.version,
        options.address_validation_now_ns,
        options.address_validation_peer,
        token,
    ) catch return error.InvalidPacket;
}

const ReceivedClientInitial = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,
    initial_secrets: quic.protection.InitialSecrets,
    coalesced_tail: []u8,

    fn deinit(self: *ReceivedClientInitial, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
        allocator.free(self.coalesced_tail);
        self.* = undefined;
    }
};

fn receiveClientInitial(
    endpoint: *quic.runtime.Endpoint,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    retry_destination_connection_id: []const u8,
    version: quic.Version,
) Error!ReceivedClientInitial {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    if (datagram.bytes.len < quic.initial_exchange.min_initial_udp_datagram_size) return error.InvalidInitialPacket;

    const header = try quic.LongHeader.parse(datagram.bytes);
    if (header.packet_type != .initial) return error.InvalidInitialPacket;
    if (retry_destination_connection_id.len == 0) {
        // RFC 9000 Section 7.2 requires a first client Initial to use a random
        // Destination Connection ID of at least 8 bytes.  A Retry follow-up is
        // different: its DCID is the server-chosen Retry SCID, which can be
        // shorter, so the accept path below validates exact equality instead.
        if (header.destination_connection_id.len < 8) return error.InvalidInitialPacket;
    } else if (!std.mem.eql(u8, header.destination_connection_id, retry_destination_connection_id)) {
        return error.InvalidInitialPacket;
    }

    if (header.version != version.wireValue()) return error.InvalidInitialPacket;
    const initial_secrets = try quic.protection.deriveInitialSecretsForVersion(version.wireValue(), header.destination_connection_id);
    const initial_info = try quic.protection.peekProtectedLongPacketInfo(
        datagram.bytes,
    );
    if (initial_info.packet_type != .initial) return error.InvalidInitialPacket;
    var packet = try quic.protection.openInitialPacket(
        endpoint.allocator,
        initial_secrets.client,
        datagram.bytes[0..initial_info.len],
        expected_packet_number,
    );
    errdefer packet.deinit(endpoint.allocator);
    const coalesced_tail = try endpoint.allocator.dupe(
        u8,
        datagram.bytes[initial_info.len..],
    );
    errdefer endpoint.allocator.free(coalesced_tail);

    var reassembler = quic.crypto_stream.Reassembler.init(endpoint.allocator, max_crypto_buffer);
    defer reassembler.deinit();
    var pos: usize = 0;
    var saw_crypto = false;
    while (pos < packet.payload.len) {
        var parsed = try quic.parseFrameOwned(endpoint.allocator, packet.payload[pos..]);
        defer parsed.deinitOwned(endpoint.allocator);
        try quic.validateFrameForPacketType(parsed.frame, .initial);
        if (parsed.frame == .crypto) {
            saw_crypto = true;
            try reassembler.insert(parsed.frame.crypto);
        }
        pos += parsed.consumed;
    }
    if (!saw_crypto) return error.MissingCryptoFrame;
    const crypto_data = try reassembler.readAllAvailable(endpoint.allocator);
    errdefer endpoint.allocator.free(crypto_data);
    return .{
        .from = datagram.from,
        .packet = packet,
        .crypto_data = crypto_data,
        .initial_secrets = initial_secrets,
        .coalesced_tail = coalesced_tail,
    };
}

fn receiveServerHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    coalesced_tail: []const u8,
    handshake_keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
) Error!quic.initial_exchange.ReceivedHandshakeCrypto {
    if (coalesced_tail.len == 0) {
        return quic.initial_exchange.receiveHandshakeCrypto(endpoint, handshake_keys, expected_packet_number, max_crypto_buffer);
    }

    const info = try quic.protection.peekProtectedLongPacketInfo(coalesced_tail);
    if (info.packet_type != .handshake or info.len != coalesced_tail.len) return error.InvalidHandshakeFlight;
    return quic.initial_exchange.openHandshakeCrypto(
        endpoint,
        from,
        coalesced_tail[0..info.len],
        handshake_keys,
        expected_packet_number,
        max_crypto_buffer,
    );
}

fn openClientEarlyData(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    coalesced_tail: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
    expected_destination_connection_id: []const u8,
    expected_source_connection_id: []const u8,
) Error!quic.zero_rtt.Packet {
    if (coalesced_tail.len == 0) return error.InvalidHandshakeFlight;
    const info = try quic.protection.peekProtectedLongPacketInfo(coalesced_tail);
    if (info.packet_type != .zero_rtt or info.len != coalesced_tail.len) {
        return error.InvalidHandshakeFlight;
    }
    var packet = try quic.zero_rtt.openBytes(
        endpoint,
        from,
        coalesced_tail,
        keys,
        expected_packet_number,
        max_frames,
    );
    errdefer packet.deinit(endpoint.allocator);
    if (!std.mem.eql(
        u8,
        packet.packet.destination_connection_id,
        expected_destination_connection_id,
    ) or
        !std.mem.eql(
            u8,
            packet.packet.source_connection_id,
            expected_source_connection_id,
        ))
    {
        return error.InvalidInitialPacket;
    }
    return packet;
}

fn validateRejectedEarlyDataTail(coalesced_tail: []const u8) Error!void {
    const info = try quic.protection.peekProtectedLongPacketInfo(coalesced_tail);
    if (info.packet_type != .zero_rtt or info.len != coalesced_tail.len) {
        return error.InvalidHandshakeFlight;
    }
    // RFC 9001 permits a server to reject 0-RTT while continuing PSK
    // resumption. The packet is deliberately left undecrypted and discarded.
}

fn establishedConnection(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    config: OneRttConfig,
    local_endpoint: quic.one_rtt.ConnectionConfig.EndpointRole,
    local_transport_parameters: quic.TransportParameters,
    peer_transport_parameters: quic.TransportParameters,
    alpn: []const u8,
    resumed: bool,
    early_data_status: quic.zero_rtt.handshake.Status,
    resumption_master_secret: [32]u8,
) Error!EstablishedConnection {
    const local_owned = try endpoint.allocator.dupe(u8, local_connection_id);
    errdefer endpoint.allocator.free(local_owned);
    const peer_owned = try endpoint.allocator.dupe(u8, peer_connection_id);
    errdefer endpoint.allocator.free(peer_owned);
    const alpn_owned = try endpoint.allocator.dupe(u8, alpn);
    errdefer endpoint.allocator.free(alpn_owned);
    var connection = try quic.one_rtt.Connection.init(endpoint, config.apply(
        peer,
        receive_keys,
        send_keys,
        local_owned,
        peer_owned,
        local_endpoint,
        local_transport_parameters,
        peer_transport_parameters,
    ));
    errdefer connection.deinit();
    return .{
        .connection = connection,
        .local_connection_id = local_owned,
        .peer_connection_id = peer_owned,
        .alpn = alpn_owned,
        .resumed = resumed,
        .early_data_status = early_data_status,
        .resumption_master_secret = resumption_master_secret,
        .peer_transport_parameters = .fromTransportParameters(
            peer_transport_parameters,
        ),
    };
}

fn clientTransportParameters(
    allocator: std.mem.Allocator,
    options: ClientOptions,
    local_transport_parameters: *quic.TransportParameters,
    encoded: *std.ArrayList(u8),
) Error![]const u8 {
    if (options.transport_parameters.len != 0) {
        local_transport_parameters.* = try quic.parseTransportParametersTyped(allocator, options.transport_parameters, .client);
        try validateClientTransportParameters(local_transport_parameters.*, options.local_connection_id, options.version, options.available_versions);
        return options.transport_parameters;
    }

    local_transport_parameters.initial_source_connection_id = options.local_connection_id;
    try validateClientTransportParameters(local_transport_parameters.*, options.local_connection_id, options.version, options.available_versions);
    try quic.encodeTransportParametersForSource(encoded, allocator, local_transport_parameters.*, .client);
    try appendVersionInformationIfAbsent(encoded, allocator, local_transport_parameters.*, options.version, options.available_versions);
    return encoded.items;
}

fn serverTransportParameters(
    allocator: std.mem.Allocator,
    options: ServerOptions,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    local_transport_parameters: *quic.TransportParameters,
    encoded: *std.ArrayList(u8),
) Error![]const u8 {
    if (options.transport_parameters.len != 0) {
        local_transport_parameters.* = try quic.parseTransportParametersTyped(allocator, options.transport_parameters, .server);
        try validateServerTransportParameters(local_transport_parameters.*, options.local_connection_id, original_destination_connection_id, retry_source_connection_id, options.version, options.available_versions, false);
        return options.transport_parameters;
    }

    local_transport_parameters.original_destination_connection_id = original_destination_connection_id;
    local_transport_parameters.initial_source_connection_id = options.local_connection_id;
    if (retry_source_connection_id.len != 0) {
        local_transport_parameters.retry_source_connection_id = retry_source_connection_id;
    }
    try validateServerTransportParameters(local_transport_parameters.*, options.local_connection_id, original_destination_connection_id, retry_source_connection_id, options.version, options.available_versions, false);
    try quic.encodeTransportParametersForSource(encoded, allocator, local_transport_parameters.*, .server);
    try appendVersionInformationIfAbsent(encoded, allocator, local_transport_parameters.*, options.version, options.available_versions);
    return encoded.items;
}

fn appendVersionInformationIfAbsent(
    encoded: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    params: quic.TransportParameters,
    version: quic.Version,
    available_versions: []const quic.Version,
) Error!void {
    if (params.version_information != null) return;
    try quic.encodeVersionInformationFromVersions(encoded, allocator, version, available_versions);
}

fn validateClientTransportParameters(
    params: quic.TransportParameters,
    initial_source_connection_id: []const u8,
    expected_version: quic.Version,
    available_versions: []const quic.Version,
) Error!void {
    try quic.validateTransportParameters(params, .client);
    if (params.initial_source_connection_id == null) return error.InvalidTransportParameter;
    if (!std.mem.eql(u8, params.initial_source_connection_id.?, initial_source_connection_id)) {
        return error.InvalidTransportParameter;
    }
    try validatePeerVersionInformation(params.version_information, expected_version, available_versions, false);
}

fn validateServerTransportParameters(
    params: quic.TransportParameters,
    initial_source_connection_id: []const u8,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    expected_version: quic.Version,
    available_versions: []const quic.Version,
    version_negotiation_processed: bool,
) Error!void {
    try quic.validateTransportParameters(params, .server);
    if (params.initial_source_connection_id == null or params.original_destination_connection_id == null) {
        return error.InvalidTransportParameter;
    }
    if (!std.mem.eql(u8, params.initial_source_connection_id.?, initial_source_connection_id)) {
        return error.InvalidTransportParameter;
    }
    if (!std.mem.eql(u8, params.original_destination_connection_id.?, original_destination_connection_id)) {
        return error.InvalidTransportParameter;
    }
    if (retry_source_connection_id.len == 0) {
        if (params.retry_source_connection_id != null) return error.InvalidTransportParameter;
    } else {
        const advertised = params.retry_source_connection_id orelse return error.InvalidTransportParameter;
        if (!std.mem.eql(u8, advertised, retry_source_connection_id)) return error.InvalidTransportParameter;
    }
    try validatePeerVersionInformation(params.version_information, expected_version, available_versions, version_negotiation_processed);
}

fn validatePeerVersionInformation(
    version_information: ?quic.VersionInformation,
    expected_version: quic.Version,
    available_versions: []const quic.Version,
    version_negotiation_processed: bool,
) Error!void {
    const info = version_information orelse {
        if (version_negotiation_processed and expected_version != .version_1) return error.InvalidTransportParameter;
        return;
    };
    if (info.chosen_version.wireValue() != expected_version.wireValue()) return error.InvalidTransportParameter;
    if (!info.containsAvailableVersion(expected_version)) return error.InvalidTransportParameter;
    if (version_negotiation_processed) {
        for (available_versions) |local| {
            if (local.wireValue() == expected_version.wireValue()) break;
            if (info.containsAvailableVersion(local)) return error.InvalidTransportParameter;
        } else {}
    }
}

const ServerFlight = struct {
    encrypted_extensions: []const u8,
    certificate: ?[]const u8 = null,
    certificate_verify: ?[]const u8 = null,
    before_finished: []const u8,
    finished: []const u8,
};

fn splitServerFlight(
    bytes: []const u8,
    selected_psk: bool,
) Error!ServerFlight {
    const ee_len = try handshakeMessageLen(bytes);
    if (ee_len >= bytes.len) return error.InvalidHandshakeFlight;
    var offset = ee_len;
    var certificate: ?[]const u8 = null;
    var certificate_verify: ?[]const u8 = null;
    if (!selected_psk) {
        const certificate_len = try handshakeMessageLen(bytes[offset..]);
        certificate = bytes[offset..][0..certificate_len];
        offset += certificate_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
        const verify_len = try handshakeMessageLen(bytes[offset..]);
        certificate_verify = bytes[offset..][0..verify_len];
        offset += verify_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
    }
    const finished_len = try handshakeMessageLen(bytes[offset..]);
    if (offset + finished_len != bytes.len) {
        return error.InvalidHandshakeFlight;
    }
    return .{
        .encrypted_extensions = bytes[0..ee_len],
        .certificate = certificate,
        .certificate_verify = certificate_verify,
        .before_finished = bytes[0..offset],
        .finished = bytes[offset..],
    };
}

fn hashServerFlightBeforeFinished(
    client_hello: []const u8,
    server_hello: []const u8,
    flight: ServerFlight,
) [32]u8 {
    return hashParts(&.{
        client_hello,
        server_hello,
        flight.before_finished,
    });
}

fn handshakeMessageLen(bytes: []const u8) Error!usize {
    if (bytes.len < 4) return error.InvalidHandshakeFlight;
    const body_len = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
    const total = 4 + body_len;
    if (total > bytes.len) return error.InvalidHandshakeFlight;
    return total;
}

fn hashParts(parts: []const []const u8) [32]u8 {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |part| sha.update(part);
    var out: [32]u8 = undefined;
    sha.final(&out);
    return out;
}

fn random32(io: std.Io, provided: ?[32]u8) std.Io.RandomSecureError![32]u8 {
    if (provided) |value| return value;
    var out: [32]u8 = undefined;
    try std.Io.randomSecure(io, &out);
    return out;
}

fn secretKey(io: std.Io, provided: ?[32]u8) std.Io.RandomSecureError![32]u8 {
    var secret = try random32(io, provided);
    // Clamp in the X25519 caller-facing layer so deterministic test vectors and
    // random production secrets follow the same scalar-shape invariant.
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
}

fn chooseAlpn(server_protocol: []const u8, client_protocols: []const []const u8) Error![]const u8 {
    for (client_protocols) |protocol| {
        if (std.mem.eql(u8, protocol, server_protocol)) return server_protocol;
    }
    return error.MissingAlpn;
}

fn ensureOfferedAlpn(offered: []const []const u8, selected: []const u8) Error!void {
    for (offered) |protocol| {
        if (std.mem.eql(u8, protocol, selected)) return;
    }
    return error.MissingAlpn;
}

test "QUIC integrated handshake establishes 1-RTT stream exchange" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };
    const client_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const server_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.endpoint, shared.cid) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(endpoint: *quic.runtime.Endpoint, cid: []const u8) !void {
            var established = try accept(endpoint, .{
                .local_connection_id = cid,
                .random = [_]u8{0x62} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            });
            defer established.deinit();
            try std.testing.expectEqualStrings("h3", established.alpn);

            var request = try established.connection.receivePacket();
            defer request.deinit(endpoint.allocator);
            try std.testing.expectEqualStrings("GET /", request.frames[0].stream.data);

            const response = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "OK", .fin = true } }};
            try established.connection.send(&response);
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(&client_endpoint, server_endpoint.address(), .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = [_]u8{0x61} ** 32,
        .x25519_secret_key = [_]u8{0x63} ** 32,
    });
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);

    const request = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /", .fin = true } }};
    try established.connection.send(&request);
    var response = try established.connection.receivePacket();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualStrings("OK", response.frames[0].stream.data);
}

test "QUIC integrated handshake emits matching NSS key logs on both roles" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_cid = [_]u8{ 9, 10, 11, 12 };
    const server_cid = [_]u8{ 13, 14, 15, 16 };
    const client_random = [_]u8{0xa5} ** 32;
    var client_output: std.Io.Writer.Allocating = .init(allocator);
    defer client_output.deinit();
    var client_log = quic.keylog.Log.init(&client_output.writer);
    var server_output: std.Io.Writer.Allocating = .init(allocator);
    defer server_output.deinit();
    var server_log = quic.keylog.Log.init(&server_output.writer);

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        keylog: *quic.keylog.Log,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = accept(shared.endpoint, .{
                .local_connection_id = shared.cid,
                .random = [_]u8{0xb6} ** 32,
                .x25519_secret_key = [_]u8{0xc7} ** 32,
                .keylog = shared.keylog,
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .keylog = &server_log,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = client_random,
            .x25519_secret_key = [_]u8{0xd8} ** 32,
            .keylog = &client_log,
        },
    );
    established.deinit();
    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualSlices(
        u8,
        client_output.written(),
        server_output.written(),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, client_output.written(), "\n"),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET " ++ ("a5" ** 32),
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "SERVER_TRAFFIC_SECRET_0 " ++ ("a5" ** 32),
    ) != null);
}

test {
    _ = @import("resumption/handshake_tests.zig");
}

test "QUIC integrated handshake propagates keylog sink failures" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var failing: std.Io.Writer = .failing;
    var keylog = quic.keylog.Log.init(&failing);
    try std.testing.expectError(
        error.WriteFailed,
        connect(&client_endpoint, server_endpoint.address(), .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .random = [_]u8{0x30} ** 32,
            .x25519_secret_key = [_]u8{0x33} ** 32,
            .keylog = &keylog,
        }),
    );
    // The client deliberately aborts once it derives handshake secrets. Wake
    // the server's pending Handshake receive with a malformed datagram so this
    // error-path test remains deterministic without closing shared I/O state.
    try client_endpoint.sendBytes(server_endpoint.address(), "invalid");
    thread.join();
    try std.testing.expect(shared.err != null);
}

test "QUIC integrated client restarts after Version Negotiation" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.endpoint, shared.cid) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(endpoint: *quic.runtime.Endpoint, cid: []const u8) !void {
            var first_initial = try endpoint.receiveBytes();
            defer first_initial.deinit(endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);
            try std.testing.expectEqual(quic.PacketType.initial, first_header.packet_type);
            try std.testing.expectEqual(quic.Version.version_1.wireValue(), first_header.version);

            const supported_versions = [_]u32{quic.Version.version_2.wireValue()};
            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(endpoint.allocator);
            try quic.writeVersionNegotiationPacket(&vn, endpoint.allocator, .{
                .destination_connection_id = first_header.source_connection_id,
                .source_connection_id = first_header.destination_connection_id,
                .versions = &supported_versions,
            });
            try endpoint.sendBytes(first_initial.from, vn.items);

            var established = try accept(endpoint, .{
                .version = .version_2,
                .available_versions = &.{.version_2},
                .local_connection_id = cid,
                .random = [_]u8{0x82} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
            });
            defer established.deinit();
            try std.testing.expectEqualStrings("h3", established.alpn);

            var request = try established.connection.receivePacket();
            defer request.deinit(endpoint.allocator);
            try std.testing.expectEqualStrings("GET /vn", request.frames[0].stream.data);

            const response = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "VN OK", .fin = true } }};
            try established.connection.send(&response);
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(&client_endpoint, server_endpoint.address(), .{
        .version = .version_1,
        .available_versions = &.{ .version_2, .version_1 },
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = [_]u8{0x81} ** 32,
        .x25519_secret_key = [_]u8{0x83} ** 32,
    });
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);

    const request = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /vn", .fin = true } }};
    try established.connection.send(&request);
    var response = try established.connection.receivePacket();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualStrings("VN OK", response.frames[0].stream.data);
}

test "QUIC integrated client rejects mismatched Version Information after VN" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const client_random = [_]u8{0xc1} ** 32;
    const client_secret_key = [_]u8{0xc3} ** 32;
    const server_random = [_]u8{0xc2} ** 32;
    const server_secret_key = try secretKey(io, [_]u8{0xc4} ** 32);

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        server_random: [32]u8,
        server_secret_key: [32]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var first_initial = try shared.endpoint.receiveBytes();
            defer first_initial.deinit(shared.endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);

            const supported_versions = [_]u32{quic.Version.version_2.wireValue()};
            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(shared.endpoint.allocator);
            try quic.writeVersionNegotiationPacket(&vn, shared.endpoint.allocator, .{
                .destination_connection_id = first_header.source_connection_id,
                .source_connection_id = first_header.destination_connection_id,
                .versions = &supported_versions,
            });
            try shared.endpoint.sendBytes(first_initial.from, vn.items);

            var client_initial = try receiveClientInitial(shared.endpoint, 0, 4096, &.{}, .version_2);
            defer client_initial.deinit(shared.endpoint.allocator);
            var parsed_client = try quic.tls_client_hello.parseClientHello(shared.endpoint.allocator, client_initial.crypto_data);
            defer parsed_client.deinit(shared.endpoint.allocator);

            const server_public = try quic.tls_client_hello.x25519PublicKey(shared.server_secret_key);
            const shared_secret = try quic.tls_client_hello.x25519SharedSecret(shared.server_secret_key, parsed_client.x25519_public_key);

            var server_hello: std.ArrayList(u8) = .empty;
            defer server_hello.deinit(shared.endpoint.allocator);
            try quic.tls_client_hello.writeServerHello(&server_hello, shared.endpoint.allocator, .{
                .random = shared.server_random,
                .x25519_public_key = server_public,
            });
            const hs_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items });
            const handshake = try quic.tls_client_hello.deriveHandshakeSecretsForVersion(quic.Version.version_2.wireValue(), shared_secret, hs_hash);

            var wrong_tp = quic.practical_transport_parameters;
            wrong_tp.original_destination_connection_id = client_initial.packet.destination_connection_id;
            wrong_tp.initial_source_connection_id = shared.cid;
            wrong_tp.version_information = .{
                .chosen_version = .version_1,
                .available_versions_wire = &[_]u8{ 0x00, 0x00, 0x00, 0x01 },
            };
            var encoded_tp: std.ArrayList(u8) = .empty;
            defer encoded_tp.deinit(shared.endpoint.allocator);
            try quic.encodeTransportParametersForSource(&encoded_tp, shared.endpoint.allocator, wrong_tp, .server);

            var encrypted_extensions: std.ArrayList(u8) = .empty;
            defer encrypted_extensions.deinit(shared.endpoint.allocator);
            try quic.tls_client_hello.writeEncryptedExtensions(&encrypted_extensions, shared.endpoint.allocator, "h3", encoded_tp.items);
            const server_finished_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items });
            const server_verify = quic.tls_client_hello.computeFinishedVerifyData(handshake.server_handshake_traffic_secret, server_finished_hash);
            var server_finished: std.ArrayList(u8) = .empty;
            defer server_finished.deinit(shared.endpoint.allocator);
            try quic.tls_client_hello.writeFinished(&server_finished, shared.endpoint.allocator, server_verify);

            var server_flight: std.ArrayList(u8) = .empty;
            defer server_flight.deinit(shared.endpoint.allocator);
            try server_flight.appendSlice(shared.endpoint.allocator, encrypted_extensions.items);
            try server_flight.appendSlice(shared.endpoint.allocator, server_finished.items);

            try quic.initial_exchange.sendCoalescedInitialHandshakeCrypto(
                shared.endpoint,
                client_initial.from,
                client_initial.initial_secrets.server,
                .{
                    .version = quic.Version.version_2.wireValue(),
                    .destination_connection_id = client_initial.packet.source_connection_id,
                    .source_connection_id = shared.cid,
                    .packet_number = 0,
                    .crypto_data = server_hello.items,
                    .max_crypto_frame_data_len = 1024,
                    .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
                },
                handshake.server_quic,
                .{
                    .version = quic.Version.version_2.wireValue(),
                    .destination_connection_id = client_initial.packet.source_connection_id,
                    .source_connection_id = shared.cid,
                    .packet_number = 0,
                    .crypto_data = server_flight.items,
                    .max_crypto_frame_data_len = 1024,
                },
            );
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .server_random = server_random,
        .server_secret_key = server_secret_key,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidTransportParameter, connect(&client_endpoint, server_endpoint.address(), .{
        .version = .version_1,
        .available_versions = &.{ .version_2, .version_1 },
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = client_random,
        .x25519_secret_key = client_secret_key,
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "QUIC client Initial carries address validation token" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const client_cid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const secret: quic.address_validation_token.Secret = [_]u8{0x4a} ** quic.address_validation_token.secret_len;
    const token = try quic.address_validation_token.encode(allocator, secret, .{
        .kind = .new_token,
        .issued_ns = 1_000,
        .lifetime_ns = 5_000,
        .peer_address = "client-path",
        .nonce = [_]u8{0x5b} ** quic.address_validation_token.nonce_len,
    });
    defer allocator.free(token);

    const secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    const random = [_]u8{0x21} ** 32;
    const secret_key = [_]u8{0x22} ** 32;
    const public_key = try quic.tls_client_hello.x25519PublicKey(try secretKey(io, secret_key));
    var params = quic.practical_transport_parameters;
    params.initial_source_connection_id = &client_cid;
    var encoded_tp: std.ArrayList(u8) = .empty;
    defer encoded_tp.deinit(allocator);
    try quic.encodeTransportParametersForSource(&encoded_tp, allocator, params, .client);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, allocator, .{
        .random = random,
        .x25519_public_key = public_key,
        .server_name = "localhost",
        .alpn_protocols = &.{"h3"},
        .transport_parameters = encoded_tp.items,
    });

    try quic.initial_exchange.sendInitialCrypto(&client_endpoint, server_endpoint.address(), secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_cid,
        .token = token,
        .packet_number = 0,
        .crypto_data = client_hello.items,
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });

    var raw = try server_endpoint.receiveBytes();
    defer raw.deinit(allocator);
    var opened = try quic.initial_exchange.openInitialCrypto(&server_endpoint, raw.from, raw.bytes, secrets.client, 0, 4096);
    defer opened.deinit(allocator);
    try std.testing.expectEqualSlices(u8, token, opened.packet.token);
    const validated = try quic.address_validation_token.validateAnySecret(
        &[_]quic.address_validation_token.Secret{secret},
        .new_token,
        .version_1,
        1_100,
        "client-path",
        opened.packet.token,
    );
    try std.testing.expectEqual(quic.address_validation_token.Kind.new_token, validated.kind);
}

test "QUIC integrated handshake succeeds after validated Retry" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const retry_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const token_secret: quic.address_validation_token.Secret = [_]u8{0x71} ** quic.address_validation_token.secret_len;
    const retry_nonce: quic.address_validation_token.Nonce = [_]u8{0x72} ** quic.address_validation_token.nonce_len;
    const client_random = [_]u8{0x73} ** 32;
    const client_secret_key = [_]u8{0x74} ** 32;
    const server_random = [_]u8{0x75} ** 32;
    const server_secret_key = [_]u8{0x76} ** 32;

    const first_initial_secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    const client_public = try quic.tls_client_hello.x25519PublicKey(try secretKey(io, client_secret_key));
    var params = quic.practical_transport_parameters;
    params.initial_source_connection_id = &client_cid;
    var encoded_tp: std.ArrayList(u8) = .empty;
    defer encoded_tp.deinit(allocator);
    try quic.encodeTransportParametersForSource(&encoded_tp, allocator, params, .client);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, allocator, .{
        .random = client_random,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .alpn_protocols = &.{"h3"},
        .transport_parameters = encoded_tp.items,
    });

    try quic.initial_exchange.sendInitialCrypto(&client_endpoint, server_endpoint.address(), first_initial_secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_cid,
        .packet_number = 0,
        .crypto_data = client_hello.items,
        .max_crypto_frame_data_len = 1024,
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });

    var first_initial = try receiveClientInitial(&server_endpoint, 0, 4096, &.{}, .version_1);
    defer first_initial.deinit(allocator);
    const retry_datagram = try quic.retry_flow.issue(allocator, .{
        .original_destination_connection_id = first_initial.packet.destination_connection_id,
        .client_source_connection_id = first_initial.packet.source_connection_id,
        .retry_source_connection_id = &retry_scid,
        .peer_address = "client-path",
        .issued_ns = 1_000,
        .lifetime_ns = 5_000,
        .nonce = retry_nonce,
        .secret = token_secret,
    });
    defer allocator.free(retry_datagram);
    try server_endpoint.sendBytes(first_initial.from, retry_datagram);

    var retry_bytes = try client_endpoint.receiveBytes();
    defer retry_bytes.deinit(allocator);
    var retry_state = try quic.retry_flow.ClientState.init(allocator, .version_1, &original_dcid, &client_cid);
    defer retry_state.deinit();
    var processed_retry = try retry_state.process(retry_bytes.bytes, .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .random = client_random,
        .x25519_secret_key = client_secret_key,
    });
    defer processed_retry.deinit(allocator);

    const secrets = [_]quic.address_validation_token.Secret{token_secret};
    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        secrets: []const quic.address_validation_token.Secret,
        odcid: []const u8,
        rscid: []const u8,
        random: [32]u8,
        secret_key: [32]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var established = try accept(shared.endpoint, .{
                .local_connection_id = shared.cid,
                .address_validation_secrets = shared.secrets,
                .address_validation_peer = "client-path",
                .address_validation_now_ns = 1_100,
                .retry_original_destination_connection_id = shared.odcid,
                .retry_source_connection_id = shared.rscid,
                .random = shared.random,
                .x25519_secret_key = shared.secret_key,
            });
            defer established.deinit();

            var request = try established.connection.receivePacket();
            defer request.deinit(shared.endpoint.allocator);
            try std.testing.expectEqualStrings("GET /retry", request.frames[0].stream.data);

            const response = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "RETRIED", .fin = true } }};
            try established.connection.send(&response);
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .secrets = &secrets,
        .odcid = &original_dcid,
        .rscid = &retry_scid,
        .random = server_random,
        .secret_key = server_secret_key,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(&client_endpoint, server_endpoint.address(), processed_retry.retry_client_options);
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);

    const request = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /retry", .fin = true } }};
    try established.connection.send(&request);
    var response = try established.connection.receivePacket();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqualStrings("RETRIED", response.frames[0].stream.data);
}

test "QUIC integrated server rejects invalid first client Initial datagrams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var short_server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer short_server.deinit();
    var short_client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer short_client.deinit();

    const valid_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const short_keys = quic.protection.deriveInitialSecrets(&valid_dcid).client;
    try quic.initial_exchange.sendInitialCrypto(&short_client, short_server.address(), short_keys, .{
        .destination_connection_id = &valid_dcid,
        .source_connection_id = &client_cid,
        .packet_number = 0,
        .crypto_data = "too small",
    });
    try std.testing.expectError(error.InvalidInitialPacket, accept(&short_server, .{
        .local_connection_id = "srv1",
        .random = [_]u8{0x52} ** 32,
        .x25519_secret_key = [_]u8{0x53} ** 32,
    }));

    var dcid_server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer dcid_server.deinit();
    var dcid_client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer dcid_client.deinit();

    const short_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const short_dcid_keys = quic.protection.deriveInitialSecrets(&short_dcid).client;
    try quic.initial_exchange.sendInitialCrypto(&dcid_client, dcid_server.address(), short_dcid_keys, .{
        .destination_connection_id = &short_dcid,
        .source_connection_id = &client_cid,
        .packet_number = 0,
        .crypto_data = "bad dcid",
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });
    try std.testing.expectError(error.InvalidInitialPacket, accept(&dcid_server, .{
        .local_connection_id = "srv2",
        .random = [_]u8{0x54} ** 32,
        .x25519_secret_key = [_]u8{0x55} ** 32,
    }));
}

test "QUIC integrated handshake applies negotiated transport parameters over QUIC v2" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3 };
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3 };

    var client_tp = quic.practical_transport_parameters;
    client_tp.max_idle_timeout = 70;
    client_tp.ack_delay_exponent = 5;
    client_tp.max_ack_delay = 35;
    client_tp.initial_max_data = 30;
    client_tp.initial_max_stream_data_bidi_local = 11;
    client_tp.initial_max_stream_data_bidi_remote = 12;
    client_tp.initial_max_stream_data_uni = 13;
    client_tp.max_datagram_frame_size = 777;
    client_tp.min_ack_delay = 1_000;

    var server_tp = quic.practical_transport_parameters;
    server_tp.max_idle_timeout = 40;
    server_tp.ack_delay_exponent = 7;
    server_tp.max_ack_delay = 45;
    server_tp.disable_active_migration = true;
    server_tp.initial_max_data = 40;
    server_tp.initial_max_stream_data_bidi_local = 21;
    server_tp.initial_max_stream_data_bidi_remote = 22;
    server_tp.initial_max_stream_data_uni = 23;
    server_tp.max_udp_payload_size = 1400;
    server_tp.max_datagram_frame_size = 888;
    server_tp.min_ack_delay = 2_000;

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        cid: []const u8,
        params: quic.TransportParameters,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.endpoint, shared.cid, shared.params) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(endpoint: *quic.runtime.Endpoint, cid: []const u8, params: quic.TransportParameters) !void {
            var established = try accept(endpoint, .{
                .local_connection_id = cid,
                .local_transport_parameters = params,
                .version = .version_2,
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .random = [_]u8{0x72} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            });
            defer established.deinit();

            try std.testing.expectEqual(quic.one_rtt.ConnectionConfig.EndpointRole.server, established.connection.config.local_endpoint);
            try std.testing.expectEqual(@as(u64, 30), established.connection.send_flow.limit);
            try std.testing.expectEqual(@as(u64, 40), established.connection.recv_flow.limit);
            try std.testing.expectEqual(@as(?u64, 11), established.connection.config.initial_send_max_stream_data_bidi_local);
            try std.testing.expectEqual(@as(?u64, 21), established.connection.config.initial_receive_max_stream_data_bidi_local);
            try std.testing.expectEqual(@as(?u64, 40), established.connection.effectiveIdleTimeoutMillis());
            try std.testing.expectEqual(@as(u64, 7), established.connection.config.local_ack_delay_exponent);
            try std.testing.expectEqual(@as(u64, 5), established.connection.config.peer_ack_delay_exponent);
            try std.testing.expectEqual(@as(u64, 35), established.connection.config.peer_max_ack_delay_ms);
            try std.testing.expectEqual(@as(?usize, 888), established.connection.config.local_max_datagram_frame_size);
            try std.testing.expectEqual(@as(?usize, 777), established.connection.config.peer_max_datagram_frame_size);
            try std.testing.expect(established.connection.config.enable_ack_frequency);
            try std.testing.expectEqual(@as(?u64, 2_000), established.connection.config.local_min_ack_delay);
            try std.testing.expectEqual(@as(?u64, 1_000), established.connection.config.peer_min_ack_delay);
            try std.testing.expectEqual(quic.congestion.Algorithm.cubic, established.connection.congestionAlgorithm());
            try std.testing.expect(established.connection.hystartEnabled());
            try std.testing.expect(!established.connection.pacingEnabled());
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid, .params = server_tp };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(&client_endpoint, server_endpoint.address(), .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .local_transport_parameters = client_tp,
        .version = .version_2,
        .initial_one_rtt_config = .{ .enable_pacing = false },
        .random = [_]u8{0x71} ** 32,
        .x25519_secret_key = [_]u8{0x73} ** 32,
    });
    defer established.deinit();

    try std.testing.expectEqual(quic.one_rtt.ConnectionConfig.EndpointRole.client, established.connection.config.local_endpoint);
    try std.testing.expectEqual(@as(u64, 40), established.connection.send_flow.limit);
    try std.testing.expectEqual(@as(u64, 30), established.connection.recv_flow.limit);
    try std.testing.expectEqual(@as(?u64, 22), established.connection.config.initial_send_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(?u64, 11), established.connection.config.initial_receive_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(?u64, 40), established.connection.effectiveIdleTimeoutMillis());
    try std.testing.expectEqual(@as(u64, 5), established.connection.config.local_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 7), established.connection.config.peer_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 45), established.connection.config.peer_max_ack_delay_ms);
    try std.testing.expectEqual(@as(?usize, 777), established.connection.config.local_max_datagram_frame_size);
    try std.testing.expectEqual(@as(?usize, 888), established.connection.config.peer_max_datagram_frame_size);
    try std.testing.expect(established.connection.config.enable_ack_frequency);
    try std.testing.expectEqual(@as(?u64, 1_000), established.connection.config.local_min_ack_delay);
    try std.testing.expectEqual(@as(?u64, 2_000), established.connection.config.peer_min_ack_delay);
    try std.testing.expectEqual(@as(usize, 1200), established.connection.congestion.max_datagram_size);
    try std.testing.expectEqual(quic.congestion.Algorithm.cubic, established.connection.congestionAlgorithm());
    try std.testing.expect(established.connection.hystartEnabled());
    try std.testing.expect(!established.connection.pacingEnabled());
    try std.testing.expectError(error.FlowControlBlocked, established.connection.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "this exceeds server's stream credit",
        .fin = false,
    } }}));

    thread.join();
    if (shared.err) |err| return err;
}

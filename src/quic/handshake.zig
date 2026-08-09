const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || quic.tls_client_hello.Error || quic.tls.auth.Error || quic.tls.client_auth.Error || quic.one_rtt.Error || quic.zero_rtt.handshake.Error || quic.zero_rtt.replay_filter.Error || quic.resumption.tls_psk.Error || quic.resumption.ticket.handshake.Error || quic.Error || std.Io.RandomSecureError || std.Io.Writer.Error || error{
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
    client_identity: ?quic.tls.client_auth.ClientIdentity = null,
    /// TLS 1.3 cipher suites offered in preference order.
    cipher_suites: []const quic.tls_client_hello.CipherSuite =
        &quic.tls_client_hello.default_cipher_suites,
};

pub const ServerPsk = struct {
    identity: []const u8,
    secret: [32]u8,
    secret_value: ?quic.tls.secret.Secret = null,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    now_ms: u64,
    age_tolerance_ms: u32 = 10_000,
    cipher_suite: quic.tls_client_hello.CipherSuite =
        .aes_128_gcm_sha256,
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
    client_auth: ?quic.tls.client_auth.ServerPolicy = null,
    /// Server preference is authoritative by default, matching rustls's
    /// provider policy and avoiding accidental client-controlled downgrade.
    cipher_suites: []const quic.tls_client_hello.CipherSuite =
        &quic.tls_client_hello.default_cipher_suites,
    cipher_suite_policy: quic.tls_client_hello.CipherSuiteSelectionPolicy =
        .server_order,
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
    resumption_master_secret: quic.tls.secret.Secret,
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

fn cipherSuiteEnabled(
    configured: []const quic.tls_client_hello.CipherSuite,
    selected: quic.tls_client_hello.CipherSuite,
) bool {
    for (configured) |suite| {
        if (suite == selected) return true;
    }
    return false;
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
        .cipher_suites = options.cipher_suites,
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
            if (!early_data.lease.session.psk_secret.eql(
                &explicit_session.psk_secret,
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
        switch (session.psk_secret.hash) {
            .sha256 => try quic.resumption.tls_psk
                .appendClientOfferWithEarlyData(
                &client_hello,
                endpoint.allocator,
                session.ticket,
                session.obfuscatedTicketAge(now_ms),
                try session.psk_secret.sha256(),
                offer_early_data,
            ),
            .sha384 => try quic.resumption.tls_psk
                .appendClientOfferWithEarlyDataSha384(
                &client_hello,
                endpoint.allocator,
                session.ticket,
                session.obfuscatedTicketAge(now_ms),
                try session.psk_secret.sha384(),
                offer_early_data,
            ),
        }
    }

    if (options.early_data) |early_data| {
        const keys =
            try quic.zero_rtt.handshake.clientKeysForSecretAndVersion(
                options.version.wireValue(),
                early_data.lease.session.cipher_suite,
                early_data.lease.session.psk_secret,
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
    if (!cipherSuiteEnabled(
        options.cipher_suites,
        parsed_server.cipher_suite,
    )) {
        return error.InvalidCipherSuite;
    }
    const offered_psk = resumption_session != null;
    if (parsed_server.selected_psk and !offered_psk) return error.InvalidServerHello;
    const selected_psk: ?quic.tls.secret.Secret = if (parsed_server.selected_psk)
        resumption_session.?.psk_secret
    else
        null;
    const shared = try quic.tls_client_hello.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const hs_hash = hashPartsForSuite(
        parsed_server.cipher_suite,
        &.{ client_hello.items, server_initial.crypto_data },
    );
    const handshake =
        try quic.tls_client_hello
            .deriveRuntimeHandshakeSecretsForVersion(
            options.version.wireValue(),
            parsed_server.cipher_suite,
            shared,
            hs_hash,
            selected_psk,
        );
    if (options.keylog) |keylog| {
        try keylog.writeHandshakeSecrets(
            client_random,
            handshake.client_handshake_traffic_secret.bytes(),
            handshake.server_handshake_traffic_secret.bytes(),
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
        !parsed_server.selected_psk and options.server_auth != null,
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
        const certificate_transcript_hash = hashPartsForSuite(
            parsed_server.cipher_suite,
            &.{
                client_hello.items,
                server_initial.crypto_data,
                server_flight.through_certificate orelse
                    return error.InvalidHandshakeFlight,
            },
        );
        try quic.tls.auth.verifyCertificateVerify(
            certificate.entries[0],
            certificate_verify,
            certificate_transcript_hash.bytes(),
        );
    } else if (server_flight.certificate != null or
        server_flight.certificate_verify != null)
    {
        return error.InvalidHandshakeFlight;
    }
    var client_certificate: std.ArrayList(u8) = .empty;
    defer client_certificate.deinit(endpoint.allocator);
    var client_certificate_verify: std.ArrayList(u8) = .empty;
    defer client_certificate_verify.deinit(endpoint.allocator);
    if (server_flight.certificate_request) |request_bytes| {
        const request = try quic.tls.client_auth.parseRequest(request_bytes);
        const identity = options.client_identity orelse
            return error.ClientCertificateRequired;
        const signer_supported = switch (identity.signer.scheme()) {
            quic.tls.auth.signature_scheme_ed25519 => request.supports_ed25519,
            quic.tls.auth.signature_scheme_ecdsa_secp256r1_sha256 => request.supports_ecdsa_p256_sha256,
            else => false,
        };
        if (!signer_supported) return error.UnsupportedSignatureScheme;
        try identity.validate();
        try quic.tls.auth.writeCertificateWithContext(
            &client_certificate,
            endpoint.allocator,
            identity.certificate_chain,
            request.request_context,
        );
        const client_certificate_transcript_hash = hashPartsForSuite(
            parsed_server.cipher_suite,
            &.{
                client_hello.items,
                server_initial.crypto_data,
                server_flight.before_finished,
                server_flight.finished,
                client_certificate.items,
            },
        );
        try quic.tls.auth.writeCertificateVerifyForRole(
            &client_certificate_verify,
            endpoint.allocator,
            identity.signer,
            client_certificate_transcript_hash.bytes(),
            .client,
        );
    }
    const server_finished = try quic.tls_client_hello.parseFinishedForHash(
        server_flight.finished,
        parsed_server.cipher_suite.hash(),
    );
    const server_finished_hash = hashPartsForSuite(
        parsed_server.cipher_suite,
        &.{
            client_hello.items,
            server_initial.crypto_data,
            server_flight.before_finished,
        },
    );
    try quic.tls_client_hello.verifyFinishedForHash(
        handshake.server_handshake_traffic_secret,
        server_finished_hash,
        server_finished,
    );
    const application_transcript_hash = hashPartsForSuite(
        parsed_server.cipher_suite,
        &.{
            client_hello.items,
            server_initial.crypto_data,
            server_flight.before_finished,
            server_flight.finished,
        },
    );
    const application =
        try quic.tls_client_hello
            .deriveRuntimeApplicationSecretsForVersion(
            options.version.wireValue(),
            parsed_server.cipher_suite,
            handshake.handshake_secret,
            application_transcript_hash,
        );

    const client_verify = try quic.tls_client_hello
        .computeFinishedVerifyDataForHash(
        handshake.client_handshake_traffic_secret,
        application_transcript_hash,
    );
    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeFinishedForHash(
        &client_finished,
        endpoint.allocator,
        client_verify,
    );

    var client_flight: std.ArrayList(u8) = .empty;
    defer client_flight.deinit(endpoint.allocator);
    try client_flight.appendSlice(
        endpoint.allocator,
        client_certificate.items,
    );
    try client_flight.appendSlice(
        endpoint.allocator,
        client_certificate_verify.items,
    );
    if (client_flight.items.len != 0) {
        const authenticated_client_hash = hashPartsForSuite(
            parsed_server.cipher_suite,
            &.{
                client_hello.items,
                server_initial.crypto_data,
                server_flight.before_finished,
                server_flight.finished,
                client_flight.items,
            },
        );
        const authenticated_client_verify =
            try quic.tls_client_hello.computeFinishedVerifyDataForHash(
                handshake.client_handshake_traffic_secret,
                authenticated_client_hash,
            );
        client_finished.clearRetainingCapacity();
        try quic.tls_client_hello.writeFinishedForHash(
            &client_finished,
            endpoint.allocator,
            authenticated_client_verify,
        );
    }
    try client_flight.appendSlice(
        endpoint.allocator,
        client_finished.items,
    );
    try quic.initial_exchange.sendHandshakeCrypto(endpoint, server_initial.from, handshake.client_quic, .{
        .version = options.version.wireValue(),
        .destination_connection_id = server_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.client_handshake_packet_number,
        .crypto_data = client_flight.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
    });

    if (options.keylog) |keylog| {
        try keylog.writeApplicationSecrets(
            client_random,
            application.client_application_traffic_secret.bytes(),
            application.server_application_traffic_secret.bytes(),
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
        try quic.tls.key_schedule.deriveResumptionMasterSecretFor(
            application.master_secret,
            hashPartsForSuite(parsed_server.cipher_suite, &.{
                client_hello.items,
                server_initial.crypto_data,
                server_flight.before_finished,
                server_flight.finished,
                client_flight.items,
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
        const configured_secret = psk.secret_value orelse
            quic.tls.secret.Secret.fromSha256(psk.secret);
        if (configured_secret.hash != psk.cipher_suite.hash()) {
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
                        .secret_value = lease.secret_value,
                        .age_add = lease.age_add,
                        .issued_at_ms = lease.issued_at_ms,
                        .lifetime_seconds = lease.lifetime_seconds,
                        .now_ms = automatic.now_ms,
                        .age_tolerance_ms = automatic.age_tolerance_ms,
                        .cipher_suite = lease.cipher_suite,
                    };
                }
            }
        }
    }
    const alpn = try chooseAlpn(options.alpn_protocol, parsed_client.alpn_protocols);
    const cipher_suite = try quic.tls_client_hello.selectCipherSuite(
        parsed_client.cipher_suites,
        options.cipher_suites,
        options.cipher_suite_policy,
    );
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
    var selected_psk: ?quic.tls.secret.Secret = null;
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
            const configured_secret = configured_psk.secret_value orelse
                quic.tls.secret.Secret.fromSha256(
                    configured_psk.secret,
                );
            if (std.mem.eql(u8, offer.identity, configured_psk.identity) and
                configured_secret.hash == cipher_suite.hash())
            {
                switch (configured_secret.hash) {
                    .sha256 => try quic.resumption.tls_psk
                        .verifyClientOffer(
                        client_initial.crypto_data,
                        offer,
                        configured_psk.identity,
                        try configured_secret.sha256(),
                    ),
                    .sha384 => try quic.resumption.tls_psk
                        .verifyClientOfferSha384(
                        client_initial.crypto_data,
                        offer,
                        configured_psk.identity,
                        try configured_secret.sha384(),
                    ),
                }
                try quic.resumption.tls_psk.validateTicketAge(offer, .{
                    .age_add = configured_psk.age_add,
                    .issued_at_ms = configured_psk.issued_at_ms,
                    .lifetime_seconds = configured_psk.lifetime_seconds,
                    .now_ms = configured_psk.now_ms,
                    .tolerance_ms = configured_psk.age_tolerance_ms,
                });
                selected_psk = configured_secret;
                const early_data_policy = options.early_data;
                if (client_offered_early_data and
                    early_data_policy != null and
                    early_data_policy.?.accept and
                    configured_psk.cipher_suite == cipher_suite)
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
                    early_data_keys = try quic.zero_rtt.handshake
                        .clientKeysForSecretAndVersion(
                        options.version.wireValue(),
                        configured_psk.cipher_suite,
                        configured_secret,
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
        .cipher_suite = cipher_suite,
    });
    const hs_hash = hashPartsForSuite(
        cipher_suite,
        &.{ client_initial.crypto_data, server_hello.items },
    );
    const handshake = try quic.tls_client_hello
        .deriveRuntimeHandshakeSecretsForVersion(
        options.version.wireValue(),
        cipher_suite,
        shared,
        hs_hash,
        selected_psk,
    );
    if (options.keylog) |keylog| {
        try keylog.writeHandshakeSecrets(
            parsed_client.random,
            handshake.client_handshake_traffic_secret.bytes(),
            handshake.server_handshake_traffic_secret.bytes(),
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
    if (options.client_auth) |client_auth| {
        var certificate_request: std.ArrayList(u8) = .empty;
        defer certificate_request.deinit(endpoint.allocator);
        try quic.tls.client_auth.writeRequest(
            &certificate_request,
            endpoint.allocator,
            &.{},
            client_auth.certificate_authorities,
        );
        try server_flight.appendSlice(
            endpoint.allocator,
            certificate_request.items,
        );
    }
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
        const certificate_transcript_hash = hashPartsForSuite(
            cipher_suite,
            &.{
                client_initial.crypto_data,
                server_hello.items,
                server_flight.items,
            },
        );
        try quic.tls.auth.writeCertificateVerify(
            &certificate_verify,
            endpoint.allocator,
            identity.signer,
            certificate_transcript_hash.bytes(),
        );
        try server_flight.appendSlice(
            endpoint.allocator,
            certificate_verify.items,
        );
    }
    const server_finished_hash = hashPartsForSuite(
        cipher_suite,
        &.{
            client_initial.crypto_data,
            server_hello.items,
            server_flight.items,
        },
    );
    const server_verify = try quic.tls_client_hello
        .computeFinishedVerifyDataForHash(
        handshake.server_handshake_traffic_secret,
        server_finished_hash,
    );
    var server_finished: std.ArrayList(u8) = .empty;
    defer server_finished.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeFinishedForHash(
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

    var client_handshake = try quic.initial_exchange.receiveHandshakeCrypto(endpoint, handshake.client_quic, 0, options.max_crypto_buffer);
    defer client_handshake.deinit(endpoint.allocator);
    const client_flight = try splitClientFlight(
        client_handshake.crypto_data,
        options.client_auth != null,
    );
    if (options.client_auth) |client_auth| {
        var certificate = try quic.tls.auth.parseCertificateWithContext(
            endpoint.allocator,
            client_flight.certificate.?,
            &.{},
        );
        defer certificate.deinit(endpoint.allocator);
        try client_auth.verifier.verifyTrust(null, certificate.entries);
        const certificate_verify =
            try quic.tls.auth.parseCertificateVerify(
                client_flight.certificate_verify.?,
            );
        const client_certificate_transcript_hash = hashPartsForSuite(
            cipher_suite,
            &.{
                client_initial.crypto_data,
                server_hello.items,
                server_flight.items,
                client_flight.certificate.?,
            },
        );
        try quic.tls.auth.verifyCertificateVerifyForRole(
            certificate.entries[0],
            certificate_verify,
            client_certificate_transcript_hash.bytes(),
            .client,
        );
    }
    const client_verify = try quic.tls_client_hello.parseFinishedForHash(
        client_flight.finished,
        cipher_suite.hash(),
    );
    const client_finished_hash = hashPartsForSuite(
        cipher_suite,
        &.{
            client_initial.crypto_data,
            server_hello.items,
            server_flight.items,
            client_flight.before_finished,
        },
    );
    try quic.tls_client_hello.verifyFinishedForHash(
        handshake.client_handshake_traffic_secret,
        client_finished_hash,
        client_verify,
    );

    const application = try quic.tls_client_hello
        .deriveRuntimeApplicationSecretsForVersion(
        options.version.wireValue(),
        cipher_suite,
        handshake.handshake_secret,
        client_finished_hash,
    );
    if (options.keylog) |keylog| {
        try keylog.writeApplicationSecrets(
            parsed_client.random,
            application.client_application_traffic_secret.bytes(),
            application.server_application_traffic_secret.bytes(),
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
        try quic.tls.key_schedule.deriveResumptionMasterSecretFor(
            application.master_secret,
            hashPartsForSuite(cipher_suite, &.{
                client_initial.crypto_data,
                server_hello.items,
                server_flight.items,
                client_flight.before_finished,
                client_flight.finished,
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
    resumption_master_secret: quic.tls.secret.Secret,
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
    certificate_request: ?[]const u8 = null,
    certificate: ?[]const u8 = null,
    certificate_verify: ?[]const u8 = null,
    through_certificate: ?[]const u8 = null,
    before_finished: []const u8,
    finished: []const u8,
};

fn splitServerFlight(
    bytes: []const u8,
    authenticated_server: bool,
) Error!ServerFlight {
    const ee_len = try handshakeMessageLen(bytes);
    if (ee_len >= bytes.len) return error.InvalidHandshakeFlight;
    var offset = ee_len;
    var certificate_request: ?[]const u8 = null;
    var certificate: ?[]const u8 = null;
    var certificate_verify: ?[]const u8 = null;
    var through_certificate: ?[]const u8 = null;
    if (offset < bytes.len and
        bytes[offset] ==
            quic.tls.client_auth.handshake_type_certificate_request)
    {
        const request_len = try handshakeMessageLen(bytes[offset..]);
        certificate_request = bytes[offset..][0..request_len];
        offset += request_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
    }
    if (authenticated_server) {
        const certificate_len = try handshakeMessageLen(bytes[offset..]);
        certificate = bytes[offset..][0..certificate_len];
        offset += certificate_len;
        through_certificate = bytes[0..offset];
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
        .certificate_request = certificate_request,
        .certificate = certificate,
        .certificate_verify = certificate_verify,
        .through_certificate = through_certificate,
        .before_finished = bytes[0..offset],
        .finished = bytes[offset..],
    };
}

const ClientFlight = struct {
    certificate: ?[]const u8 = null,
    certificate_verify: ?[]const u8 = null,
    before_finished: []const u8,
    finished: []const u8,
};

fn splitClientFlight(
    bytes: []const u8,
    authenticated: bool,
) Error!ClientFlight {
    var offset: usize = 0;
    var certificate: ?[]const u8 = null;
    var certificate_verify: ?[]const u8 = null;
    if (authenticated) {
        const certificate_len = try handshakeMessageLen(bytes);
        certificate = bytes[0..certificate_len];
        offset = certificate_len;
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
    return quic.tls.transcript.hash(parts);
}

fn hashPartsForSuite(
    suite: quic.tls_client_hello.CipherSuite,
    parts: []const []const u8,
) quic.tls.transcript.Digest {
    return quic.tls.transcript.hashFor(suite.hash(), parts);
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

test {
    _ = @import("handshake/tests.zig");
}

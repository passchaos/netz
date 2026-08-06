const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || quic.tls_client_hello.Error || quic.one_rtt.Error || quic.Error || std.Io.RandomSecureError || error{
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
            .active_connection_id_limit = std.math.cast(usize, local_transport_parameters.active_connection_id_limit) orelse std.math.maxInt(usize),
            .local_max_idle_timeout_ms = local_transport_parameters.max_idle_timeout,
            .peer_max_idle_timeout_ms = peer_transport_parameters.max_idle_timeout,
            .local_ack_delay_exponent = local_transport_parameters.ack_delay_exponent,
            .peer_ack_delay_exponent = peer_transport_parameters.ack_delay_exponent,
            .peer_max_ack_delay_ms = peer_transport_parameters.max_ack_delay,
            .peer_disable_active_migration = peer_transport_parameters.disable_active_migration,
            .peer_preferred_address = peer_transport_parameters.preferred_address,
            .local_max_datagram_frame_size = if (local_transport_parameters.max_datagram_frame_size) |size| std.math.cast(usize, size) orelse std.math.maxInt(usize) else null,
            .peer_max_datagram_frame_size = if (peer_transport_parameters.max_datagram_frame_size) |size| std.math.cast(usize, size) orelse std.math.maxInt(usize) else null,
        };
    }
};

pub const EstablishedConnection = struct {
    connection: quic.one_rtt.Connection,
    local_connection_id: []u8,
    peer_connection_id: []u8,
    alpn: []u8,

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
    const initial_secrets = quic.protection.deriveInitialSecretsForVersion(options.version.wireValue(), initial_destination_connection_id);

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
        return connectAttempt(endpoint, peer, negotiated.clientOptions(options), true);
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
    const shared = try quic.tls_client_hello.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const hs_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data });
    const handshake = quic.tls_client_hello.deriveHandshakeSecretsForVersion(options.version.wireValue(), shared, hs_hash);

    var server_handshake = try receiveServerHandshakeCrypto(
        endpoint,
        server_initial.from,
        server_datagram.bytes[server_initial_info.len..],
        handshake.server_quic,
        0,
        options.max_crypto_buffer,
    );
    defer server_handshake.deinit(endpoint.allocator);
    const server_flight = try splitServerFlight(server_handshake.crypto_data);
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
    const server_finished = try quic.tls_client_hello.parseFinished(server_flight.finished);
    const server_finished_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data, server_flight.encrypted_extensions });
    try quic.tls_client_hello.verifyFinished(handshake.server_handshake_traffic_secret, server_finished_hash, server_finished);

    const client_finished_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data, server_flight.encrypted_extensions, server_flight.finished });
    const client_verify = quic.tls_client_hello.computeFinishedVerifyData(handshake.client_handshake_traffic_secret, client_finished_hash);
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

    const app_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data, server_flight.encrypted_extensions, server_flight.finished, client_finished.items });
    const application = quic.tls_client_hello.deriveApplicationSecretsForVersion(options.version.wireValue(), handshake.handshake_secret, app_hash);
    return try establishedConnection(
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
    );
}

pub fn accept(endpoint: *quic.runtime.Endpoint, options: ServerOptions) Error!EstablishedConnection {
    try validateConfiguredVersions(options.version, options.available_versions);
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
    const alpn = try chooseAlpn(options.alpn_protocol, parsed_client.alpn_protocols);
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

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeServerHello(&server_hello, endpoint.allocator, .{
        .random = server_random,
        .x25519_public_key = server_public,
    });
    const hs_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items });
    const handshake = quic.tls_client_hello.deriveHandshakeSecretsForVersion(options.version.wireValue(), shared, hs_hash);

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
    try quic.tls_client_hello.writeEncryptedExtensions(&encrypted_extensions, endpoint.allocator, alpn, transport_parameters);
    const server_finished_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items });
    const server_verify = quic.tls_client_hello.computeFinishedVerifyData(handshake.server_handshake_traffic_secret, server_finished_hash);
    var server_finished: std.ArrayList(u8) = .empty;
    defer server_finished.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeFinished(&server_finished, endpoint.allocator, server_verify);

    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(endpoint.allocator);
    try server_flight.appendSlice(endpoint.allocator, encrypted_extensions.items);
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
    const client_finished_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items, server_finished.items });
    try quic.tls_client_hello.verifyFinished(handshake.client_handshake_traffic_secret, client_finished_hash, client_verify);

    const app_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items, server_finished.items, client_finished.crypto_data });
    const application = quic.tls_client_hello.deriveApplicationSecretsForVersion(options.version.wireValue(), handshake.handshake_secret, app_hash);
    const established = try establishedConnection(
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
    );
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

    fn deinit(self: *ReceivedClientInitial, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
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
    const initial_secrets = quic.protection.deriveInitialSecretsForVersion(version.wireValue(), header.destination_connection_id);
    var packet = try quic.protection.openInitialPacket(endpoint.allocator, initial_secrets.client, datagram.bytes, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);

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
    try quic.encodeTransportParameters(encoded, allocator, local_transport_parameters.*);
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
    try quic.encodeTransportParameters(encoded, allocator, local_transport_parameters.*);
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
    finished: []const u8,
};

fn splitServerFlight(bytes: []const u8) Error!ServerFlight {
    const ee_len = try handshakeMessageLen(bytes);
    if (ee_len >= bytes.len) return error.InvalidHandshakeFlight;
    const finished_len = try handshakeMessageLen(bytes[ee_len..]);
    if (ee_len + finished_len != bytes.len) return error.InvalidHandshakeFlight;
    return .{
        .encrypted_extensions = bytes[0..ee_len],
        .finished = bytes[ee_len..],
    };
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
            const handshake = quic.tls_client_hello.deriveHandshakeSecretsForVersion(quic.Version.version_2.wireValue(), shared_secret, hs_hash);

            var wrong_tp = quic.practical_transport_parameters;
            wrong_tp.original_destination_connection_id = client_initial.packet.destination_connection_id;
            wrong_tp.initial_source_connection_id = shared.cid;
            wrong_tp.version_information = .{
                .chosen_version = .version_1,
                .available_versions_wire = &[_]u8{ 0x00, 0x00, 0x00, 0x01 },
            };
            var encoded_tp: std.ArrayList(u8) = .empty;
            defer encoded_tp.deinit(shared.endpoint.allocator);
            try quic.encodeTransportParameters(&encoded_tp, shared.endpoint.allocator, wrong_tp);

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
    try quic.encodeTransportParameters(&encoded_tp, allocator, params);

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
    try quic.encodeTransportParameters(&encoded_tp, allocator, params);

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
    try std.testing.expectEqual(@as(usize, 1200), established.connection.congestion.max_datagram_size);
    try std.testing.expectError(error.FlowControlBlocked, established.connection.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "this exceeds server's stream credit",
        .fin = false,
    } }}));

    thread.join();
    if (shared.err) |err| return err;
}

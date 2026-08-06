const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || quic.tls_client_hello.Error || quic.one_rtt.Error || quic.Error || std.Io.RandomSecureError || error{
    InvalidHandshakeFlight,
    MissingCryptoFrame,
    MissingAlpn,
};

pub const ClientOptions = struct {
    /// QUIC v1 Initial secrets are derived from the client's first destination
    /// connection id.  Keeping it explicit lets callers coordinate Retry or
    /// externally chosen connection-id policy above this minimal runtime.
    original_destination_connection_id: []const u8,
    local_connection_id: []const u8,
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &.{"h3"},
    /// Optional raw override for callers that need full control over the TLS
    /// QUIC transport-parameter extension.  When empty, netz emits
    /// `local_transport_parameters` plus the required connection-id parameter.
    transport_parameters: []const u8 = &.{},
    local_transport_parameters: quic.TransportParameters = quic.practical_transport_parameters,
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

pub fn connect(endpoint: *quic.runtime.Endpoint, peer: net.IpAddress, options: ClientOptions) Error!EstablishedConnection {
    const client_secret = try secretKey(endpoint.io, options.x25519_secret_key);
    const client_public = try quic.tls_client_hello.x25519PublicKey(client_secret);
    const client_random = try random32(endpoint.io, options.random);
    const initial_secrets = quic.protection.deriveInitialSecrets(options.original_destination_connection_id);

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
        .destination_connection_id = options.original_destination_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.client_initial_packet_number,
        .crypto_data = client_hello.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
        .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
    });

    var server_datagram = try endpoint.receiveBytes();
    defer server_datagram.deinit(endpoint.allocator);
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
    const handshake = quic.tls_client_hello.deriveHandshakeSecrets(shared, hs_hash);

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
        .destination_connection_id = server_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.client_handshake_packet_number,
        .crypto_data = client_finished.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
    });

    const app_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data, server_flight.encrypted_extensions, server_flight.finished, client_finished.items });
    const application = quic.tls_client_hello.deriveApplicationSecrets(handshake.handshake_secret, app_hash);
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
    var client_initial = try receiveClientInitial(endpoint, 0, options.max_crypto_buffer);
    defer client_initial.deinit(endpoint.allocator);

    var parsed_client = try quic.tls_client_hello.parseClientHello(endpoint.allocator, client_initial.crypto_data);
    defer parsed_client.deinit(endpoint.allocator);
    const alpn = try chooseAlpn(options.alpn_protocol, parsed_client.alpn_protocols);
    const peer_transport_parameters = try quic.parseTransportParametersTyped(
        endpoint.allocator,
        parsed_client.transport_parameters,
        .client,
    );
    try validateClientTransportParameters(peer_transport_parameters, client_initial.packet.source_connection_id);

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
    const handshake = quic.tls_client_hello.deriveHandshakeSecrets(shared, hs_hash);

    var local_transport_parameters = options.local_transport_parameters;
    var encoded_transport_parameters: std.ArrayList(u8) = .empty;
    defer encoded_transport_parameters.deinit(endpoint.allocator);
    const transport_parameters = try serverTransportParameters(
        endpoint.allocator,
        options,
        client_initial.packet.destination_connection_id,
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
            .destination_connection_id = client_initial.packet.source_connection_id,
            .source_connection_id = options.local_connection_id,
            .packet_number = options.server_initial_packet_number,
            .crypto_data = server_hello.items,
            .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
            .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
        },
        handshake.server_quic,
        .{
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
    const application = quic.tls_client_hello.deriveApplicationSecrets(handshake.handshake_secret, app_hash);
    return try establishedConnection(
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

fn receiveClientInitial(endpoint: *quic.runtime.Endpoint, expected_packet_number: u64, max_crypto_buffer: usize) Error!ReceivedClientInitial {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    if (datagram.bytes.len < quic.initial_exchange.min_initial_udp_datagram_size) return error.InvalidInitialPacket;

    const header = try quic.LongHeader.parse(datagram.bytes);
    if (header.packet_type != .initial) return error.InvalidInitialPacket;
    // RFC 9000 Section 7.2 requires a first client Initial to use a random
    // Destination Connection ID of at least 8 bytes.  Server endpoints rely on
    // that DCID for Initial secret derivation and route bootstrap.
    if (header.destination_connection_id.len < 8) return error.InvalidInitialPacket;

    const initial_secrets = quic.protection.deriveInitialSecrets(header.destination_connection_id);
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
        try validateClientTransportParameters(local_transport_parameters.*, options.local_connection_id);
        return options.transport_parameters;
    }

    local_transport_parameters.initial_source_connection_id = options.local_connection_id;
    try validateClientTransportParameters(local_transport_parameters.*, options.local_connection_id);
    try quic.encodeTransportParameters(encoded, allocator, local_transport_parameters.*);
    return encoded.items;
}

fn serverTransportParameters(
    allocator: std.mem.Allocator,
    options: ServerOptions,
    original_destination_connection_id: []const u8,
    local_transport_parameters: *quic.TransportParameters,
    encoded: *std.ArrayList(u8),
) Error![]const u8 {
    if (options.transport_parameters.len != 0) {
        local_transport_parameters.* = try quic.parseTransportParametersTyped(allocator, options.transport_parameters, .server);
        try validateServerTransportParameters(local_transport_parameters.*, options.local_connection_id, original_destination_connection_id);
        return options.transport_parameters;
    }

    local_transport_parameters.original_destination_connection_id = original_destination_connection_id;
    local_transport_parameters.initial_source_connection_id = options.local_connection_id;
    try validateServerTransportParameters(local_transport_parameters.*, options.local_connection_id, original_destination_connection_id);
    try quic.encodeTransportParameters(encoded, allocator, local_transport_parameters.*);
    return encoded.items;
}

fn validateClientTransportParameters(params: quic.TransportParameters, initial_source_connection_id: []const u8) Error!void {
    try quic.validateTransportParameters(params, .client);
    if (params.initial_source_connection_id == null) return error.InvalidTransportParameter;
    if (!std.mem.eql(u8, params.initial_source_connection_id.?, initial_source_connection_id)) {
        return error.InvalidTransportParameter;
    }
}

fn validateServerTransportParameters(
    params: quic.TransportParameters,
    initial_source_connection_id: []const u8,
    original_destination_connection_id: []const u8,
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

test "QUIC integrated handshake applies negotiated transport parameters" {
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
    client_tp.initial_max_data = 30;
    client_tp.initial_max_stream_data_bidi_local = 11;
    client_tp.initial_max_stream_data_bidi_remote = 12;
    client_tp.initial_max_stream_data_uni = 13;

    var server_tp = quic.practical_transport_parameters;
    server_tp.initial_max_data = 40;
    server_tp.initial_max_stream_data_bidi_local = 21;
    server_tp.initial_max_stream_data_bidi_remote = 22;
    server_tp.initial_max_stream_data_uni = 23;
    server_tp.max_udp_payload_size = 1400;

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
                .random = [_]u8{0x72} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            });
            defer established.deinit();

            try std.testing.expectEqual(quic.one_rtt.ConnectionConfig.EndpointRole.server, established.connection.config.local_endpoint);
            try std.testing.expectEqual(@as(u64, 30), established.connection.send_flow.limit);
            try std.testing.expectEqual(@as(u64, 40), established.connection.recv_flow.limit);
            try std.testing.expectEqual(@as(?u64, 11), established.connection.config.initial_send_max_stream_data_bidi_local);
            try std.testing.expectEqual(@as(?u64, 21), established.connection.config.initial_receive_max_stream_data_bidi_local);
        }
    };

    var shared = Shared{ .endpoint = &server_endpoint, .cid = &server_cid, .params = server_tp };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try connect(&client_endpoint, server_endpoint.address(), .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .local_transport_parameters = client_tp,
        .random = [_]u8{0x71} ** 32,
        .x25519_secret_key = [_]u8{0x73} ** 32,
    });
    defer established.deinit();

    try std.testing.expectEqual(quic.one_rtt.ConnectionConfig.EndpointRole.client, established.connection.config.local_endpoint);
    try std.testing.expectEqual(@as(u64, 40), established.connection.send_flow.limit);
    try std.testing.expectEqual(@as(u64, 30), established.connection.recv_flow.limit);
    try std.testing.expectEqual(@as(?u64, 22), established.connection.config.initial_send_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(?u64, 11), established.connection.config.initial_receive_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(usize, 1200), established.connection.congestion.max_datagram_size);
    try std.testing.expectError(error.FlowControlBlocked, established.connection.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "this exceeds server's stream credit",
        .fin = false,
    } }}));

    thread.join();
    if (shared.err) |err| return err;
}

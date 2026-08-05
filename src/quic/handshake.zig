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
    transport_parameters: []const u8 = &.{},
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
    transport_parameters: []const u8 = &.{},
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
    initial_send_max_data: u64 = std.math.maxInt(u62),
    initial_receive_max_data: u64 = std.math.maxInt(u62),
    receive_window: u64 = 64 * 1024,
    initial_send_max_stream_data: u64 = std.math.maxInt(u62),
    initial_receive_max_stream_data: u64 = std.math.maxInt(u62),
    stream_receive_window: u64 = 64 * 1024,

    fn apply(
        self: OneRttConfig,
        peer: net.IpAddress,
        receive_keys: quic.protection.PacketProtectionKeys,
        send_keys: quic.protection.PacketProtectionKeys,
        local_connection_id: []const u8,
        peer_connection_id: []const u8,
    ) quic.one_rtt.ConnectionConfig {
        return .{
            .peer = peer,
            .receive_keys = receive_keys,
            .send_keys = send_keys,
            .local_connection_id = local_connection_id,
            .peer_connection_id = peer_connection_id,
            .max_ack_ranges = self.max_ack_ranges,
            .max_frames_per_packet = self.max_frames_per_packet,
            .initial_send_max_data = self.initial_send_max_data,
            .initial_receive_max_data = self.initial_receive_max_data,
            .receive_window = self.receive_window,
            .initial_send_max_stream_data = self.initial_send_max_stream_data,
            .initial_receive_max_stream_data = self.initial_receive_max_stream_data,
            .stream_receive_window = self.stream_receive_window,
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

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, endpoint.allocator, .{
        .random = client_random,
        .x25519_public_key = client_public,
        .server_name = options.server_name,
        .alpn_protocols = options.alpn_protocols,
        .transport_parameters = options.transport_parameters,
    });

    try quic.initial_exchange.sendInitialCrypto(endpoint, peer, initial_secrets.client, .{
        .destination_connection_id = options.original_destination_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.client_initial_packet_number,
        .crypto_data = client_hello.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
    });

    var server_initial = try quic.initial_exchange.receiveInitialCrypto(endpoint, initial_secrets.server, 0, options.max_crypto_buffer);
    defer server_initial.deinit(endpoint.allocator);
    const parsed_server = try quic.tls_client_hello.parseServerHello(server_initial.crypto_data);
    const shared = try quic.tls_client_hello.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const hs_hash = hashParts(&.{ client_hello.items, server_initial.crypto_data });
    const handshake = quic.tls_client_hello.deriveHandshakeSecrets(shared, hs_hash);

    var server_handshake = try quic.initial_exchange.receiveHandshakeCrypto(endpoint, handshake.server_quic, 0, options.max_crypto_buffer);
    defer server_handshake.deinit(endpoint.allocator);
    const server_flight = try splitServerFlight(server_handshake.crypto_data);
    const encrypted_extensions = try quic.tls_client_hello.parseEncryptedExtensions(server_flight.encrypted_extensions);
    try ensureOfferedAlpn(options.alpn_protocols, encrypted_extensions.alpn);
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
        encrypted_extensions.alpn,
    );
}

pub fn accept(endpoint: *quic.runtime.Endpoint, options: ServerOptions) Error!EstablishedConnection {
    var client_initial = try receiveClientInitial(endpoint, 0, options.max_crypto_buffer);
    defer client_initial.deinit(endpoint.allocator);

    var parsed_client = try quic.tls_client_hello.parseClientHello(endpoint.allocator, client_initial.crypto_data);
    defer parsed_client.deinit(endpoint.allocator);
    const alpn = try chooseAlpn(options.alpn_protocol, parsed_client.alpn_protocols);

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

    try quic.initial_exchange.sendInitialCrypto(endpoint, client_initial.from, client_initial.initial_secrets.server, .{
        .destination_connection_id = client_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.server_initial_packet_number,
        .crypto_data = server_hello.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
    });

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeEncryptedExtensions(&encrypted_extensions, endpoint.allocator, alpn, options.transport_parameters);
    const server_finished_hash = hashParts(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items });
    const server_verify = quic.tls_client_hello.computeFinishedVerifyData(handshake.server_handshake_traffic_secret, server_finished_hash);
    var server_finished: std.ArrayList(u8) = .empty;
    defer server_finished.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeFinished(&server_finished, endpoint.allocator, server_verify);

    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(endpoint.allocator);
    try server_flight.appendSlice(endpoint.allocator, encrypted_extensions.items);
    try server_flight.appendSlice(endpoint.allocator, server_finished.items);
    try quic.initial_exchange.sendHandshakeCrypto(endpoint, client_initial.from, handshake.server_quic, .{
        .destination_connection_id = client_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .packet_number = options.server_handshake_packet_number,
        .crypto_data = server_flight.items,
        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
    });

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
    const header = try quic.LongHeader.parse(datagram.bytes);
    const initial_secrets = quic.protection.deriveInitialSecrets(header.destination_connection_id);
    var packet = try quic.protection.openInitialPacket(endpoint.allocator, initial_secrets.client, datagram.bytes, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);

    var reassembler = quic.crypto_stream.Reassembler.init(endpoint.allocator, max_crypto_buffer);
    defer reassembler.deinit();
    var pos: usize = 0;
    var saw_crypto = false;
    while (pos < packet.payload.len) {
        const parsed = try quic.parseFrame(packet.payload[pos..]);
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

fn establishedConnection(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    config: OneRttConfig,
    alpn: []const u8,
) Error!EstablishedConnection {
    const local_owned = try endpoint.allocator.dupe(u8, local_connection_id);
    errdefer endpoint.allocator.free(local_owned);
    const peer_owned = try endpoint.allocator.dupe(u8, peer_connection_id);
    errdefer endpoint.allocator.free(peer_owned);
    const alpn_owned = try endpoint.allocator.dupe(u8, alpn);
    errdefer endpoint.allocator.free(alpn_owned);
    var connection = try quic.one_rtt.Connection.init(endpoint, config.apply(peer, receive_keys, send_keys, local_owned, peer_owned));
    errdefer connection.deinit();
    return .{
        .connection = connection,
        .local_connection_id = local_owned,
        .peer_connection_id = peer_owned,
        .alpn = alpn_owned,
    };
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

const std = @import("std");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");

const ReceivedClientInitialForTest = struct {
    from: std.Io.net.IpAddress,
    packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,
    initial_secrets: quic.protection.InitialSecrets,
    coalesced_tail: []u8,

    fn deinit(self: *ReceivedClientInitialForTest, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
        allocator.free(self.coalesced_tail);
        self.* = undefined;
    }
};

fn receiveClientInitialForTest(
    endpoint: *quic.runtime.Endpoint,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    retry_destination_connection_id: []const u8,
    version: quic.Version,
) handshake.Error!ReceivedClientInitialForTest {
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

fn clampSecret(value: [32]u8) [32]u8 {
    var secret = value;
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
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
            var established = try handshake.accept(endpoint, .{
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

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), .{
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
            var established = handshake.accept(shared.endpoint, .{
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

    var established = try handshake.connect(
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
    _ = @import("../resumption/handshake_tests.zig");
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
            var established = handshake.accept(shared.endpoint, .{
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
        handshake.connect(&client_endpoint, server_endpoint.address(), .{
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

            var established = try handshake.accept(endpoint, .{
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

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), .{
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
    const server_secret_key = clampSecret([_]u8{0xc4} ** 32);

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

            var client_initial = try receiveClientInitialForTest(shared.endpoint, 0, 4096, &.{}, .version_2);
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
            const hs_hash = quic.tls.transcript.hash(&.{ client_initial.crypto_data, server_hello.items });
            const handshake_secrets = try quic.tls_client_hello.deriveHandshakeSecretsForVersion(quic.Version.version_2.wireValue(), shared_secret, hs_hash);

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
            const server_finished_hash = quic.tls.transcript.hash(&.{ client_initial.crypto_data, server_hello.items, encrypted_extensions.items });
            const server_verify = quic.tls_client_hello.computeFinishedVerifyData(handshake_secrets.server_handshake_traffic_secret, server_finished_hash);
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
                handshake_secrets.server_quic,
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

    try std.testing.expectError(error.InvalidTransportParameter, handshake.connect(&client_endpoint, server_endpoint.address(), .{
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
    const public_key = try quic.tls_client_hello.x25519PublicKey(clampSecret(secret_key));
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
    const client_public = try quic.tls_client_hello.x25519PublicKey(clampSecret(client_secret_key));
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

    var first_initial = try receiveClientInitialForTest(&server_endpoint, 0, 4096, &.{}, .version_1);
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
            var established = try handshake.accept(shared.endpoint, .{
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

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), processed_retry.retry_client_options);
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
    try std.testing.expectError(error.InvalidInitialPacket, handshake.accept(&short_server, .{
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
    try std.testing.expectError(error.InvalidInitialPacket, handshake.accept(&dcid_server, .{
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
            var established = try handshake.accept(endpoint, .{
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

    var established = try handshake.connect(&client_endpoint, server_endpoint.address(), .{
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

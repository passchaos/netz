//! HTTP/3 early-request admission and replay tests.

const std = @import("std");
const http3 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const BodyChunk = runtime.BodyChunk;
const BodyWriteProgress = runtime.BodyWriteProgress;
const Client = runtime.Client;
const DevelopmentBodyWriteProgress = runtime.DevelopmentBodyWriteProgress;
const EarlyRequestDisposition = runtime.EarlyRequestDisposition;
const HandshakeClient = runtime.HandshakeClient;
const HandshakeServer = runtime.HandshakeServer;
const HandshakeServerSession = runtime.HandshakeServerSession;
const HandshakeSessionOptions = runtime.HandshakeSessionOptions;
const InformationalResponseHead = runtime.InformationalResponseHead;
const MultiplexedInformationalObserver = runtime.MultiplexedInformationalObserver;
const OwnedConnectDatagram = runtime.OwnedConnectDatagram;
const OwnedRequestBatch = runtime.OwnedRequestBatch;
const PreparedEarlyRequest = runtime.PreparedEarlyRequest;
const ProtectedClient = runtime.ProtectedClient;
const ProtectedServer = runtime.ProtectedServer;
const Server = runtime.Server;
const ServerPush = runtime.ServerPush;
const ShutdownState = runtime.ShutdownState;
const applyControlStreamFrameForRole = runtime.applyControlStreamFrameForRole;
const applyControlStreamFrameForRoleWithPushes = runtime.applyControlStreamFrameForRoleWithPushes;
const client_control_stream_id = runtime.client_control_stream_id;
const client_qpack_decoder_stream_id = runtime.client_qpack_decoder_stream_id;
const client_qpack_encoder_stream_id = runtime.client_qpack_encoder_stream_id;
const complete_request = runtime.complete_request;
const configureQpackEncoderFromPeerSettings = runtime.configureQpackEncoderFromPeerSettings;
const connect_datagram = runtime.connect_datagram;
const default_paced_request_body_chunk_bytes = runtime.default_paced_request_body_chunk_bytes;
const default_paced_response_body_chunk_bytes = runtime.default_paced_response_body_chunk_bytes;
const drainConnectDatagrams = runtime.drainConnectDatagrams;
const encodePushMessages = runtime.encodePushMessages;
const finishServedConnectionWithDeadline = runtime.finishServedConnectionWithDeadline;
const first_server_push_stream_id = runtime.first_server_push_stream_id;
const handshake_client_pool = runtime.handshake_client_pool;
const paced_body = runtime.paced_body;
const push_aggregate = runtime.push_aggregate;
const quic = runtime.quic;
const tls_protocol = @import("../../tls/stream/version.zig").Protocol;
const receiveRuntimeStreamBytes = runtime.receiveRuntimeStreamBytes;
const resolvePacedBodyChunkBytes = runtime.resolvePacedBodyChunkBytes;
const responseHeadErrorAtFin = runtime.responseHeadErrorAtFin;
const response_scheduler = runtime.response_scheduler;
const routeConnectDatagramsFromPacket = runtime.routeConnectDatagramsFromPacket;
const sendConnectionFrames = runtime.sendConnectionFrames;
const sendConnectionMessage = runtime.sendConnectionMessage;
const sendConnectionQpackEncoderInstructions = runtime.sendConnectionQpackEncoderInstructions;
const sendConnectionSettings = runtime.sendConnectionSettings;
const sendProtectedFrames = runtime.sendProtectedFrames;
const sendProtectedSettings = runtime.sendProtectedSettings;
const server_control_stream_id = runtime.server_control_stream_id;
const server_qpack_decoder_stream_id = runtime.server_qpack_decoder_stream_id;
const server_qpack_encoder_stream_id = runtime.server_qpack_encoder_stream_id;
const server_response = runtime.server_response;
const sleepResponseSchedulerDelayUntil = runtime.sleepResponseSchedulerDelayUntil;
const stream_lifecycle = runtime.stream_lifecycle;
const testing = runtime.testing;
const validateHandshakeSessionOptions = runtime.validateHandshakeSessionOptions;

test "HTTP/3 established client rejects untyped early bidirectional stream" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x45} ** quic.protection.secret_len,
    );
    var established = try quic.handshake.establishPreconfigured(
        &client_endpoint,
        server_endpoint.address(),
        .client,
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "early-client",
            .peer_connection_id = "early-server",
        },
    );
    defer established.deinit();
    try established.connection.importSentEarlyData(0, &.{.{ .stream = .{
        .stream_id = 0,
        .data = "early request",
        .fin = true,
    } }});
    try std.testing.expectEqual(
        @as(u64, 4),
        established.connection.nextLocalBidirectionalStreamId(),
    );

    try std.testing.expectError(
        error.UnexpectedEarlyData,
        HandshakeClient.initEstablished(
            &client_endpoint,
            server_endpoint.address(),
            established,
            .{},
        ),
    );
}

test "HTTP/3 established client rejects unknown early unidirectional streams" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x46} ** quic.protection.secret_len,
    );
    var established = try quic.handshake.establishPreconfigured(
        &client_endpoint,
        server_endpoint.address(),
        .client,
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "early-uni-client",
            .peer_connection_id = "early-uni-server",
        },
    );
    defer established.deinit();
    try established.connection.importSentEarlyData(0, &.{.{ .stream = .{
        .stream_id = 2,
        .data = "unknown early unidirectional bytes",
    } }});
    try std.testing.expectEqual(
        @as(u64, 6),
        established.connection.nextLocalUnidirectionalStreamId(),
    );
    try std.testing.expectError(
        error.StreamCreationError,
        HandshakeClient.initEstablished(
            &client_endpoint,
            server_endpoint.address(),
            established,
            .{},
        ),
    );
}

test "HTTP/3 handshake adopts accepted typed early request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-early-request-ticket";
    const psk = [_]u8{0x47} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 17,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    const request_options: http3.Request = .{
        .method = "HEAD",
        .path = "/early-request",
        .authority = "localhost",
    };
    var early = try PreparedEarlyRequest.init(
        allocator,
        request_options,
        .{},
        .{},
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{ 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
    const client_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    const server_cid = [_]u8{ 0x54, 0x55, 0x56, 0x57 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x58} ** 32,
            .x25519_secret_key = [_]u8{0x59} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 17,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "typed-request-1",
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 20,
                .max_retries = 3,
                .should_drop = struct {
                    fn first(attempt: u8) bool {
                        return attempt == 0;
                    }
                }.first,
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.accepted,
                session.earlyDataStatus(),
            );
            try std.testing.expectEqual(true, session.wasTlsSessionResumed().?);
            try std.testing.expectEqual(
                tls_protocol.tls13,
                session.negotiatedTlsProtocol().?,
            );
            var early_request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer early_request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), early_request.stream_id);
            try std.testing.expect(early_request.was_early_data);
            try std.testing.expect(
                session.established.connection
                    .recvStreamReceivedEarlyData(early_request.stream_id),
            );
            try std.testing.expectEqualStrings(
                "/early-request",
                early_request.request.path,
            );
            try session.sendResponse(early_request.stream_id, .{
                .status = 200,
                .request_method = "HEAD",
                .body = "suppressed-head-body",
            });

            var next_request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer next_request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), next_request.stream_id);
            try std.testing.expect(!next_request.was_early_data);
            try std.testing.expect(
                !session.established.connection
                    .recvStreamReceivedEarlyData(next_request.stream_id),
            );
            try session.sendResponse(next_request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x5a} ** 32,
            .x25519_secret_key = [_]u8{0x5b} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .handshake_recovery = .{
                .initial_pto_ms = 5,
                .max_pto_ms = 10,
                .max_retries = 5,
            },
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.accepted,
        connected.disposition,
    );
    try std.testing.expect(client.established.connection.next_packet_number > 1);
    var early_response = try client.receiveResponseWithTimeout(
        early.stream_id,
        .fromSeconds(2),
    );
    defer early_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), early_response.response.status);
    try std.testing.expectEqualStrings("", early_response.response.body);
    const next_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/after-early",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 4), next_id);
    var next_response = try client.receiveResponseWithTimeout(
        next_id,
        .fromSeconds(2),
    );
    defer next_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), next_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 rejected typed early request remains explicit and replayable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-rejected-early-request-ticket";
    const psk = [_]u8{0x5c} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 23,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    const request_options: http3.Request = .{
        .method = "GET",
        .path = "/replayed-after-rejection",
        .authority = "localhost",
    };
    var early = try PreparedEarlyRequest.init(
        allocator,
        request_options,
        .{},
        .{},
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 };
    const client_cid = [_]u8{ 0x68, 0x69, 0x6a, 0x6b };
    const server_cid = [_]u8{ 0x6c, 0x6d, 0x6e, 0x6f };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x70} ** 32,
            .x25519_secret_key = [_]u8{0x71} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 23,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .cipher_suites = &.{.chacha20_poly1305_sha256},
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "typed-request-rejected",
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.rejected,
                session.established.early_data_status,
            );
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expectEqualStrings(
                "/replayed-after-rejection",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x72} ** 32,
            .x25519_secret_key = [_]u8{0x73} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.rejected,
        connected.disposition,
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

    var response = try client.requestWithTimeout(
        request_options,
        .fromSeconds(2),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 typed early request remains replayable after Version Negotiation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-vn-early-request-ticket";
    const psk = [_]u8{0x76} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 29,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    const request_options: http3.Request = .{
        .method = "GET",
        .path = "/replayed-after-vn",
        .authority = "localhost",
    };
    var early = try PreparedEarlyRequest.init(
        allocator,
        request_options,
        .{},
        .{},
    );
    defer early.deinit();

    const original_dcid = [_]u8{ 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e };
    const client_cid = [_]u8{ 0x7f, 0x80, 0x81, 0x82 };
    const server_cid = [_]u8{ 0x83, 0x84, 0x85, 0x86 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .version = .version_2,
            .available_versions = &.{.version_2},
            .local_connection_id = &server_cid,
            .random = [_]u8{0x87} ** 32,
            .x25519_secret_key = [_]u8{0x88} ** 32,
            .key_exchange_groups = &.{.x25519},
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 29,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const endpoint = &self.server.quic_server.endpoint;
            var first_initial = try endpoint.receiveBytes();
            defer first_initial.deinit(endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);
            try std.testing.expectEqual(
                quic.Version.version_1.wireValue(),
                first_header.version,
            );
            try std.testing.expectEqual(
                quic.PacketType.initial,
                first_header.packet_type,
            );
            var first_early = try endpoint.receiveBytes();
            defer first_early.deinit(endpoint.allocator);
            const early_info = try quic.protection
                .peekProtectedLongPacketInfo(first_early.bytes);
            try std.testing.expectEqual(
                quic.Version.version_1.wireValue(),
                early_info.version,
            );
            try std.testing.expectEqual(
                quic.protection.ProtectedLongPacketType.zero_rtt,
                early_info.packet_type,
            );
            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(endpoint.allocator);
            try quic.writeVersionNegotiationPacket(
                &vn,
                endpoint.allocator,
                .{
                    .destination_connection_id = first_header.source_connection_id,
                    .source_connection_id = first_header.destination_connection_id,
                    .versions = &.{quic.Version.version_2.wireValue()},
                },
            );
            try endpoint.sendBytes(first_initial.from, vn.items);

            var session = try self.server.accept();
            defer session.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                session.earlyDataStatus(),
            );
            try std.testing.expectEqual(
                tls_protocol.tls13,
                session.negotiatedTlsProtocol().?,
            );
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expectEqualStrings(
                "/replayed-after-vn",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .version = .version_1,
            .available_versions = &.{ .version_2, .version_1 },
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x89} ** 32,
            .x25519_secret_key = [_]u8{0x8a} ** 32,
            .key_exchange_groups = &.{.x25519},
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.rejected,
        connected.disposition,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        client.earlyDataStatus(),
    );
    try std.testing.expectEqual(true, client.wasTlsSessionResumed().?);
    try std.testing.expectEqual(
        tls_protocol.tls13,
        client.negotiatedTlsProtocol().?,
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.established.connection.next_packet_number);

    var response = try client.requestWithTimeout(
        request_options,
        .fromSeconds(2),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(.consumed, lease.state);
}

test "HTTP/3 typed early request rejects mismatched local settings before connect" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = "settings-mismatch-ticket",
        .psk = [_]u8{0x74} ** 32,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 29,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var early = try PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/settings-mismatch",
            .authority = "localhost",
        },
        .{ .h3_datagram = true },
        .{},
    );
    defer early.deinit();

    try std.testing.expectError(
        error.InvalidSetting,
        HandshakeClient.connectWithEarlyRequest(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{},
            .{ .handshake = .{
                .original_destination_connection_id = "12345678",
                .local_connection_id = "client",
                .server_name = "localhost",
                .resumption_now_ms = 1500,
                .resumption_server_id = "localhost:443",
            } },
            &early,
            &cache,
            &lease,
        ),
    );
    try std.testing.expectEqual(.active, lease.state);
    try std.testing.expect(cache.ownsActiveLease(lease));
    try std.testing.expectError(
        error.ExcessiveLoad,
        HandshakeClient.connectWithEarlyRequest(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{},
            .{
                .handshake = .{
                    .original_destination_connection_id = "12345678",
                    .local_connection_id = "client",
                    .server_name = "localhost",
                    .resumption_now_ms = 1500,
                    .resumption_server_id = "localhost:443",
                },
                .session = .{ .max_concurrent_request_streams = 0 },
            },
            &early,
            &cache,
            &lease,
        ),
    );
    try std.testing.expectEqual(.active, lease.state);
    try std.testing.expect(cache.ownsActiveLease(lease));

    var tiny_limits = quic.practical_transport_parameters;
    tiny_limits.initial_max_streams_uni = 2;
    var limited_lease = lease;
    limited_lease.session.transport_parameters =
        .fromTransportParameters(tiny_limits);
    try std.testing.expectError(
        error.StreamLimitExceeded,
        early.validateTransportLimits(.{}, .{ .handshake = .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
        } }, &limited_lease),
    );
}

test "HTTP/3 accepted early request rejects reduced peer settings" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var remembered_transport = quic.practical_transport_parameters;
    remembered_transport.max_datagram_frame_size = 1200;
    const remembered_settings: http3.Settings = .{ .h3_datagram = true };
    const ticket = "h3-reduced-settings-ticket";
    const psk = [_]u8{0x75} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 31,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            remembered_transport,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var early = try PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/reduced-settings",
            .authority = "localhost",
        },
        .{},
        remembered_settings,
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{ 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d };
    const client_cid = [_]u8{ 0x7e, 0x7f, 0x80, 0x81 };
    const server_cid = [_]u8{ 0x82, 0x83, 0x84, 0x85 };
    var server_transport = quic.practical_transport_parameters;
    server_transport.max_datagram_frame_size = 1200;
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .local_transport_parameters = server_transport,
            .random = [_]u8{0x86} ** 32,
            .x25519_secret_key = [_]u8{0x87} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 31,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "typed-request-settings-reduced",
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .local_transport_parameters = remembered_transport,
            .random = [_]u8{0x88} ** 32,
            .x25519_secret_key = [_]u8{0x89} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.accepted,
        connected.disposition,
    );
    try std.testing.expectError(
        error.InvalidSetting,
        client.receiveResponseWithTimeout(
            early.stream_id,
            .fromSeconds(2),
        ),
    );
    try std.testing.expect(
        client.established.connection.closing() or
            client.established.connection.closed(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

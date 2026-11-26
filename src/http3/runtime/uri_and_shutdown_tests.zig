//! HTTP/3 URI, Alt-Svc, cancellation, and shutdown tests.

const std = @import("std");
const NativeSendIo = @import("../../internal/testing/deadline_send_io.zig").Native;
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

test "HTTP/3 handshake client requests from URI endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x01, 0x11 };
    const client_cid = [_]u8{ 0xa2, 0xb2, 0xc2, 0xd2 };
    const server_cid = [_]u8{ 0xa3, 0xb3, 0xc3, 0xd3 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa4} ** 32,
            .x25519_secret_key = [_]u8{0xa5} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/uri", request.request.path);
            try std.testing.expectEqualStrings("127.0.0.1", request.request.authority.?[0..9]);
            try session.sendResponse(request.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var uri_buf: [64]u8 = undefined;
    const uri_text = try std.fmt.bufPrint(&uri_buf, "https://127.0.0.1:{d}/uri", .{server.address().ip4.port});
    const uri = try std.Uri.parse(uri_text);
    var response = try HandshakeClient.requestUri(allocator, io, .{ .ip4 = .loopback(0) }, uri, .{}, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xa6} ** 32,
            .x25519_secret_key = [_]u8{0xa7} ** 32,
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 URI request deadline covers the response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    const server_cid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        deadline: std.Io.Clock.Timestamp,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            // A received request proves the handshake and request send both
            // completed inside the caller's budget. Hold the response past
            // that same absolute timestamp so only response waiting can time
            // out, independent of host load.
            try self.deadline.wait(
                session.established.connection.endpoint.io,
            );
            try std.Io.sleep(
                session.established.connection.endpoint.io,
                .fromMilliseconds(25),
                .awake,
            );
        }
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    var shared = Shared{ .server = &server, .deadline = deadline };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var uri_buf: [64]u8 = undefined;
    const uri_text = try std.fmt.bufPrint(
        &uri_buf,
        "https://127.0.0.1:{d}/deadline",
        .{server.address().getPort()},
    );
    const uri = try std.Uri.parse(uri_text);
    try std.testing.expectError(
        error.Timeout,
        HandshakeClient.requestUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{},
            .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
            .{
                .connect_timeout = .fromSeconds(1),
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .random = [_]u8{0xd3} ** 32,
                    .x25519_secret_key = [_]u8{0xd4} ** 32,
                },
            },
            deadline,
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client requests via Alt-Svc target" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_cid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc };
    const server_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const uri = try std.Uri.parse("https://origin.example/alt");

    try std.testing.expectError(error.InvalidHeader, HandshakeClient.requestUriAltSvc(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{ .alpn = "h2", .connect_host = "127.0.0.1", .origin_host = "origin.example", .port = 443 },
        .{},
        .{},
        .{ .handshake = .{ .original_destination_connection_id = &original_dcid, .local_connection_id = &client_cid } },
    ));

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb4} ** 32,
            .x25519_secret_key = [_]u8{0xb5} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/alt", request.request.path);
            try std.testing.expectEqualStrings("origin.example", request.request.authority.?);
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const server_address = server.address();
    var alt_svc_value_buf: [64]u8 = undefined;
    const alt_svc_value = try std.fmt.bufPrint(
        &alt_svc_value_buf,
        "h3=\"127.0.0.1:{d}\"; ma=60",
        .{server_address.ip4.port},
    );
    const alt_svc_headers = [_]http3.Qpack.HeaderField{
        .{ .name = "alt-svc", .value = alt_svc_value },
    };
    var response = try HandshakeClient.requestUriAltSvcHeader(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        &alt_svc_headers,
        .{},
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xb6} ** 32,
            .x25519_secret_key = [_]u8{0xb7} ** 32,
        } },
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake server retains interleaved request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const client_cid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c };
    const server_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x63} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), first.stream_id);
            try std.testing.expectEqualStrings("/first", first.request.path);
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_streams.count(),
            );

            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), second.stream_id);
            try std.testing.expectEqualStrings("/second", second.request.path);
            try std.testing.expectEqual(
                @as(usize, 0),
                session.request_streams.count(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x61} ** 32,
                .x25519_secret_key = [_]u8{0x62} ** 32,
            },
        },
    );
    defer client.deinit();

    try sendConnectionSettings(
        &client.established.connection,
        &client.critical_stream_send_scratch,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = 4,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try client.established.connection.send(&frames);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client cancellation reaches server" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c };
    const client_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x77} ** 32,
                .x25519_secret_key = [_]u8{0x78} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectError(
                error.RequestCancelled,
                session.receiveRequest(),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                session.request_streams.count(),
            );
            const reset = session.established.connection.streamResetReceived(0) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.request_cancelled),
                reset.application_error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x75} ** 32,
                .x25519_secret_key = [_]u8{0x76} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.cancelRequest(
        0,
        http3.ApplicationErrorCode.request_cancelled,
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake server ORIGIN deadline is transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const client_cid = [_]u8{ 0xa9, 0xaa, 0xab, 0xac };
    const server_cid = [_]u8{ 0xad, 0xae, 0xaf, 0xb0 };
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
            .random = [_]u8{0xb1} ** 32,
            .x25519_secret_key = [_]u8{0xb2} ** 32,
        } },
    );
    defer server.deinit();

    const origin = "https://alt.example";
    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        sent: std.Io.Event = .unset,
        observed: std.Io.Event = .unset,
        checked: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.sent.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            try std.testing.expect(!session.control.local_origin_set_sent);
            try std.testing.expectError(
                error.Timeout,
                session.sendOriginsWithDeadline(
                    &.{origin},
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                session.control_send.next_offset,
            );
            try std.testing.expect(!session.control.local_origin_set_sent);
            try session.sendOriginsWithTimeout(
                &.{origin},
                .fromSeconds(2),
            );
            try std.testing.expect(session.control.local_origin_set_sent);
            self.checked = true;
            self.sent.set(self.io);
            try self.observed.wait(self.io);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.observed.set(io);
        thread.join();
    };

    var client = try HandshakeClient.connect(
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
            .random = [_]u8{0xb3} ** 32,
            .x25519_secret_key = [_]u8{0xb4} ** 32,
        } },
    );
    defer client.deinit();

    try shared.sent.wait(io);
    if (shared.err) |err| return err;
    while (!client.peerOriginSetInitialized()) {
        try client.pollControlWithTimeout(.fromSeconds(2));
    }
    try std.testing.expect(client.peerOriginKnown(
        try http3.originFromSerialized(origin),
    ));
    shared.observed.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.checked);
}

test "HTTP/3 handshake server performs two-phase graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80 };
    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x8b} ** 32,
                .x25519_secret_key = [_]u8{0x8c} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            try std.testing.expectError(
                error.Timeout,
                session.initiateShutdownWithDeadline(.{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                session.control_send.next_offset,
            );
            try std.testing.expectEqual(
                stream_lifecycle.ShutdownState.active,
                session.request_lifecycle.state(),
            );
            try session.initiateShutdownWithTimeout(.fromSeconds(2));
            try session.completeShutdownWithTimeout(.fromSeconds(2));
            try std.testing.expectEqual(
                @as(?u64, 4),
                session.control.local_goaway_id,
            );
            try std.testing.expect(!session.drainComplete());
            try session.sendResponse(request.stream_id, .{ .status = 204 });
            try std.testing.expect(session.drainComplete());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x89} ** 32,
                .x25519_secret_key = [_]u8{0x8a} ** 32,
            },
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/graceful",
        .authority = "localhost",
    });
    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 4)
    {
        try client.receiveProgress();
    }
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expectEqual(@as(?u64, 4), client.control.peer_goaway_id);
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-graceful",
    }));
}

test "HTTP/3 serveConnection shutdown deadline covers GOAWAY send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var session = try HandshakeServerSession.initPreconfigured(
        &endpoint,
        peer_endpoint.address(),
        .{},
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "shutdown-server",
            .peer_connection_id = "shutdown-client",
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer session.deinit();
    try sendConnectionSettings(
        &session.established.connection,
        &session.critical_stream_send_scratch,
        &session.control,
        &session.control_send,
        &session.qpack_encoder_send,
        &session.qpack_encoder_prefix_sent,
        &session.qpack_decoder_send,
        &session.qpack_decoder_prefix_sent,
        session.options,
        server_control_stream_id,
    );

    const fixed_delegate_io = endpoint.io;
    var fixed: NativeSendIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .now_ns = .init(1_000_000),
    };
    defer fixed.backend.deinit();
    endpoint.io = fixed.io();
    defer endpoint.io = fixed_delegate_io;

    quic.one_rtt.testing.exhaustPacingAt(
        &session.established.connection,
        @intCast(fixed.now_ns.load(.acquire)),
    );
    const packet_number = session.established.connection.next_packet_number;
    const control_offset = session.control_send.next_offset;
    try std.testing.expectError(
        error.RecoveryDrainTimeout,
        finishServedConnectionWithDeadline(&session, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed.send_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixed.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(
        packet_number,
        session.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, session.control_send.next_offset);
    try std.testing.expectEqual(@as(?u64, null), session.control.local_goaway_id);
    try std.testing.expectEqual(
        ShutdownState.active,
        session.request_lifecycle.state(),
    );
}

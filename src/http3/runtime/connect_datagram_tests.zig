//! HTTP/3 CONNECT datagram and detached response-head tests.

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

test "HTTP/3 CONNECT datagrams round trip over a detached handshake stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xc0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xc8, 0xc9, 0xca, 0xcb };
    const server_cid = [_]u8{ 0xcc, 0xcd, 0xce, 0xcf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        },
        .session = .{ .local_settings = settings },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        response_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var head_event = try session.receiveRequestEvent();
            defer head_event.deinit(self.server.allocator);
            const stream_id = head_event.message.stream_id;
            try std.testing.expectError(
                error.InvalidStatus,
                session.acceptConnectResponse(stream_id, .{
                    .status = 404,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidStatus,
                session.tryAcceptConnectResponse(stream_id, .{
                    .status = 404,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidHeader,
                session.acceptConnectResponse(stream_id, .{
                    .status = 200,
                }),
            );
            try std.testing.expectError(
                error.InvalidStatus,
                session.acceptConnectResponse(stream_id, .{
                    .status = 204,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidContentLength,
                session.acceptConnectResponse(stream_id, .{
                    .status = 200,
                    .body = "not a head-only admission",
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidContentLength,
                session.acceptConnectResponse(stream_id, .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "content-length",
                        .value = "0",
                    }},
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expect(
                session.maxConnectDatagramPayloadSize(stream_id) == null,
            );
            try session.acceptConnectResponse(stream_id, .{
                .status = 200,
                .request_method = "CONNECT",
                .extended_connect = true,
            });
            self.response_sent.set(self.server.quic_server.endpoint.io);
            var incoming = try session.receiveConnectDatagramWithTimeout(
                stream_id,
                .fromSeconds(2),
            );
            defer incoming.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("client datagram", incoming.payload);
            try session.sendConnectDatagram(stream_id, "server datagram");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        thread.join();
    };
    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xc1} ** 32,
            .x25519_secret_key = [_]u8{0xc2} ** 32,
        },
        .session = .{ .local_settings = settings },
    });
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/capsule",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "connect-udp" }},
    }, null);
    try shared.response_sent.wait(io);
    _ = try client.receivePeerSettingsWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    while (true) {
        if (try client.pollDetachedResponseHead(stream_id)) |head_value| {
            var head = head_value;
            defer head.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            const date = server_response.headerValue(head.headers, "date") orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                @as(usize, server_response.date_value_len),
                date.len,
            );
            break;
        }
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try client.detachResponseStream(stream_id);
    try std.testing.expect(client.connectDatagramsNegotiated());
    try std.testing.expect(client.maxConnectDatagramPayloadSize(stream_id).? > 0);
    try client.sendConnectDatagram(stream_id, "client datagram");
    var incoming = try client.receiveConnectDatagramWithTimeout(
        stream_id,
        .fromSeconds(2),
    );
    defer incoming.deinit(allocator);
    try std.testing.expectEqualStrings("server datagram", incoming.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 detached response head registers preceding push promise" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    const client_cid = [_]u8{ 0xb8, 0xb9, 0xba, 0xbb };
    const server_cid = [_]u8{ 0xbc, 0xbd, 0xbe, 0xbf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
    };

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
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
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
            var request = try session.receiveRequestEvent();
            defer request.deinit(self.server.allocator);
            if (request != .message or
                request.message.value != .head or
                request.message.value.head != .request)
            {
                return error.TestUnexpectedResult;
            }
            while (session.control.peer_max_push_id != 0) {
                try session.receiveRequestPacket();
            }
            _ = try session.sendResponseWithPush(
                request.message.stream_id,
                .{
                    .status = 200,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                },
                .{
                    .push_id = 0,
                    .request = .{
                        .method = "GET",
                        .path = "/detached-asset",
                        .authority = "localhost",
                    },
                    .response = .{ .status = 204 },
                },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

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
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(0);
    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/detached-push",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "test" }},
    }, null);

    while (true) {
        if (try client.pollDetachedResponseHead(stream_id)) |head_value| {
            var head = head_value;
            defer head.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            break;
        }
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try std.testing.expect(client.push_streams.hasPromise(0));
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.promiseCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 detached response head reports terminal missing headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const server_cid = [_]u8{ 0xac, 0xad, 0xae, 0xaf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
    };

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
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        saw_stop: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequestEvent();
            defer request.deinit(self.server.allocator);
            const stream_id = request.message.stream_id;
            try session.established.connection.send(&.{.{ .stream = .{
                .stream_id = stream_id,
                .data = &.{},
                .fin = true,
            } }});
            while (!self.saw_stop) {
                var packet = try session.established.connection
                    .receivePacketTimeout(.{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } });
                defer packet.deinit(self.server.allocator);
                for (packet.frames) |frame| switch (frame) {
                    .stop_sending => |stop| if (stop.stream_id == stream_id) {
                        try std.testing.expectEqual(
                            @as(u64, http3.ApplicationErrorCode.message_error),
                            stop.application_error_code,
                        );
                        self.saw_stop = true;
                    },
                    else => {},
                };
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

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
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/detached-missing",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "test" }},
    }, null);

    while (client.established.connection.recvStreamStats(stream_id) == null or
        client.established.connection.recvStreamStats(stream_id).?.final_size ==
            null)
    {
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try std.testing.expectError(
        error.MissingStatus,
        client.pollDetachedResponseHead(stream_id),
    );
    try std.testing.expect(!client.request_lifecycle.contains(stream_id));
    try std.testing.expect(!client.established.connection.closing());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 detached response head closes on terminal truncated frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };
    const client_cid = [_]u8{ 0x98, 0x99, 0x9a, 0x9b };
    const server_cid = [_]u8{ 0x9c, 0x9d, 0x9e, 0x9f };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
    };

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
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
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
            var request = try session.receiveRequestEvent();
            defer request.deinit(self.server.allocator);
            try session.established.connection.send(&.{.{
                .stream = .{
                    .stream_id = request.message.stream_id,
                    // HEADERS type without its payload-length varint.
                    .data = &.{http3.FrameType.headers},
                    .fin = true,
                },
            }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

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
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/detached-truncated",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "test" }},
    }, null);

    while (client.established.connection.recvStreamStats(stream_id) == null or
        client.established.connection.recvStreamStats(stream_id).?.final_size ==
            null)
    {
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try std.testing.expectError(
        error.BufferTooShort,
        client.pollDetachedResponseHead(stream_id),
    );
    const close = quic.one_rtt.testing.localCloseInfo(
        &client.established.connection,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(close.application);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.frame_error),
        close.error_code,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 paced request send preserves detached CONNECT during backpressure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };

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
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        detached: std.Io.Event = .unset,
        send_terminal: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.detached.set(self.server.quic_server.endpoint.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var head_event = try session.receiveRequestEvent();
            defer head_event.deinit(self.server.allocator);
            const stream_id = head_event.message.stream_id;
            try session.startResponse(stream_id, .{
                .status = 200,
                .request_method = "CONNECT",
                .extended_connect = true,
            }, null);
            try session.detachRequestStream(stream_id);
            self.detached.set(self.server.quic_server.endpoint.io);
            try self.send_terminal.wait(
                self.server.quic_server.endpoint.io,
            );
            try session.sendResponseBodyPaced(stream_id, &.{}, true);
            // Unblock the client only after peer FIN is already socket-visible.
            // Its paced send must process that detached terminal packet before
            // consuming this later credit update and retrying successfully.
            const credit = [_]quic.Frame{.{ .max_stream_data = .{
                .stream_id = stream_id,
                .maximum_stream_data = 64 * 1024,
            } }};
            try session.established.connection.send(&credit);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_terminal.set(io);
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
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/backpressure",
        .authority = "localhost",
        .headers = &.{.{
            .name = ":protocol",
            .value = "connect-udp",
        }},
    }, null);
    try shared.detached.wait(io);
    while (true) {
        if (try client.pollDetachedResponseHead(stream_id)) |head_value| {
            var head = head_value;
            defer head.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            break;
        }
        try client.established.connection
            .servicePacketServicingTimersDeadline(.fromNow(io, .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        }));
    }
    try client.detachResponseStream(stream_id);

    const blocked_at = try quic.one_rtt.testing
        .clampSendStreamLimitToUsed(
        &client.established.connection,
        stream_id,
    );
    shared.send_terminal.set(io);
    try client.sendRequestBodyPaced(stream_id, "x", false);
    try std.testing.expect(
        quic.one_rtt.testing.sendStreamLimit(
            &client.established.connection,
            stream_id,
        ).? > blocked_at,
    );
    try std.testing.expectEqual(
        connect_datagram.Terminal.peer_fin,
        (try client.connect_datagrams.terminal(stream_id)).?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 CONNECT datagram invalid QSID closes the connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const local_cid = "h3-dgram-local";
    const peer_cid = "h3-dgram-peer";
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = peer_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    // Injecting at the transport queue isolates the RFC 9297 parser/error
    // mapping from packet protection while still exercising real close state.
    try quic.one_rtt.testing.injectReceivedDatagram(&connection, &.{});
    try std.testing.expectError(
        error.BufferTooShort,
        drainConnectDatagrams(&registry, &connection),
    );
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.datagram_error,
        connection.close_info.?.error_code,
    );
    try std.testing.expect(connection.close_info.?.application);
    try std.testing.expectEqualStrings(
        "invalid-http-datagram",
        connection.close_info.?.reason_phrase,
    );
    try std.testing.expectEqual(@as(usize, 0), registry.associations.items.len);
}

test "HTTP/3 CONNECT datagrams preserve terminal frame ordering" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "order-local",
        .peer_connection_id = "order-peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    try registry.register(4);

    try quic.one_rtt.testing.injectReceivedDatagram(&connection, &.{
        0x00, 'b', 'e', 'f', 'o', 'r', 'e',
    });
    try quic.one_rtt.testing.injectReceivedDatagram(&connection, &.{
        0x00, 'a', 'f', 't', 'e', 'r',
    });
    const frames = [_]quic.Frame{
        .{ .datagram = .{ .data = &.{
            0x00, 'b', 'e', 'f', 'o', 'r', 'e',
        }, .length_present = true } },
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            .final_size = 0,
        } },
        .{ .datagram = .{ .data = &.{
            0x00, 'a', 'f', 't', 'e', 'r',
        }, .length_present = true } },
    };
    try routeConnectDatagramsFromPacket(&registry, &connection, &frames, 0);
    var before = (try registry.poll(0)).?;
    defer before.deinit(allocator);
    try std.testing.expectEqualStrings("before", before.payload);
    try std.testing.expectEqualDeep(
        connect_datagram.Terminal{
            .peer_reset = http3.ApplicationErrorCode.request_cancelled,
        },
        (try registry.drainedTerminal(0)).?,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(4));
    try std.testing.expectEqual(@as(usize, 0), connection.datagramReceiveQueueLen());

    registry.unregister(0);
    try registry.register(0);
    try quic.one_rtt.testing.injectReceivedDatagram(
        &connection,
        &.{ 0x00, 'l', 'a', 't', 'e' },
    );
    const close_frames = [_]quic.Frame{
        .{ .application_close = .{
            .error_code = 0,
            .reason_phrase = "done",
        } },
        .{ .datagram = .{ .data = &.{ 0x00, 'l', 'a', 't', 'e' } } },
    };
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &close_frames,
        0,
    );
    try std.testing.expectEqual(@as(?OwnedConnectDatagram, null), try registry.poll(0));
    try std.testing.expectEqual(
        connect_datagram.Terminal.connection_closed,
        (try registry.drainedTerminal(0)).?,
    );

    // A terminal frame does not need to share a packet with a DATAGRAM. Mark
    // it immediately so a DATAGRAM arriving in a later packet is discarded
    // without entering the bounded application queue.
    registry.unregister(0);
    try registry.register(0);
    const fin_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = &.{},
        .fin = true,
    } }};
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &fin_frames,
        1,
    );
    try std.testing.expectEqual(
        connect_datagram.Terminal.peer_fin,
        (try registry.drainedTerminal(0)).?,
    );
    try quic.one_rtt.testing.injectReceivedDatagramForPacket(
        &connection,
        2,
        &.{ 0x00, 'l', 'a', 't', 'e' },
    );
    const late_frames = [_]quic.Frame{.{ .datagram = .{
        .data = &.{ 0x00, 'l', 'a', 't', 'e' },
    } }};
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &late_frames,
        2,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.datagramReceiveQueueLen(),
    );
}

test "HTTP/3 CONNECT datagram routing isolates GRO packet copies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "gro-local",
        .peer_connection_id = "gro-peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 4,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    try quic.one_rtt.testing.injectReceivedDatagramForPacket(
        &connection,
        10,
        &.{ 0x00, 'o', 'n', 'e' },
    );
    try quic.one_rtt.testing.injectReceivedDatagramForPacket(
        &connection,
        11,
        &.{ 0x00, 't', 'w', 'o' },
    );
    const first_frames = [_]quic.Frame{.{ .datagram = .{
        .data = &.{ 0x00, 'o', 'n', 'e' },
    } }};
    const second_frames = [_]quic.Frame{.{ .datagram = .{
        .data = &.{ 0x00, 't', 'w', 'o' },
    } }};
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &first_frames,
        10,
    );
    try std.testing.expectEqual(@as(usize, 1), connection.datagramReceiveQueueLen());
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &second_frames,
        11,
    );
    var first = (try registry.poll(0)).?;
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.payload);
    var second = (try registry.poll(0)).?;
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.payload);
    try std.testing.expectEqual(@as(usize, 0), connection.datagramReceiveQueueLen());
}

test "HTTP/3 CONNECT datagram validates transport-dropped payloads" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdb} ** quic.protection.secret_len,
    );
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "drop-local",
        .peer_connection_id = "drop-peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 0,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = &.{} } }};
    try std.testing.expectError(
        error.BufferTooShort,
        routeConnectDatagramsFromPacket(
            &registry,
            &connection,
            &frames,
            12,
        ),
    );
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.datagram_error,
        connection.close_info.?.error_code,
    );
}

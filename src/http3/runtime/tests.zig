//! HTTP/3 runtime tests moved out of the runtime root.

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

test {
    _ = @import("concurrent_tests.zig");
    _ = @import("connect_datagram_tests.zig");
    _ = @import("handshake_deadline_tests.zig");
    _ = @import("request/cancel_deadline_tests.zig");
    _ = @import("uri_and_shutdown_tests.zig");
    _ = @import("request/finish_rejected_deadline_tests.zig");
    _ = @import("receive/request_failure_retry_tests.zig");
    _ = @import("receive/field_value_tests.zig");
    _ = @import("receive/priority_metadata_tests.zig");
    _ = @import("receive/response_failure_retry_tests.zig");
    _ = @import("receive/message_data_tests.zig");
    _ = @import("receive/failure_ownership_tests.zig");
    _ = @import("stream/push/failure_tests.zig");
}

test "HTTP/3 response scheduler delay respects caller deadline" {
    const FixedIo = struct {
        now_ns: i96 = 1_000_000,
        sleep_calls: usize = 0,
        slept_ns: i96 = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            timeout: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            const target = switch (timeout) {
                .none => return error.Canceled,
                .duration => |duration| self.now_ns + duration.raw.nanoseconds,
                .deadline => |deadline| deadline.raw.nanoseconds,
            };
            self.slept_ns += target - self.now_ns;
            self.now_ns = target;
        }
    };
    var fixed: FixedIo = .{};
    var vtable = std.Io.Threaded.init(std.testing.allocator, .{});
    defer vtable.deinit();
    var io_vtable = vtable.io().vtable.*;
    io_vtable.now = FixedIo.now;
    io_vtable.sleep = FixedIo.sleep;
    const io = std.Io{ .userdata = &fixed, .vtable = &io_vtable };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(10),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.Timeout,
        sleepResponseSchedulerDelayUntil(io, std.time.ns_per_s, deadline),
    );
    try std.testing.expectEqual(@as(usize, 1), fixed.sleep_calls);
    try std.testing.expectEqual(@as(i96, 10 * std.time.ns_per_ms), fixed.slept_ns);
}

test "HTTP/3 detached response FIN distinguishes missing head from truncated frame" {
    try std.testing.expectEqual(
        error.MissingStatus,
        responseHeadErrorAtFin(&.{}),
    );
    try std.testing.expectEqual(
        error.BufferTooShort,
        responseHeadErrorAtFin(&.{0x01}),
    );
}

test "HTTP/3 handshake sessions resolve direction-aware paced body defaults" {
    try std.testing.expectEqual(
        default_paced_request_body_chunk_bytes,
        resolvePacedBodyChunkBytes(
            .{},
            default_paced_request_body_chunk_bytes,
        ).paced_body_chunk_bytes,
    );
    try std.testing.expectEqual(
        default_paced_response_body_chunk_bytes,
        resolvePacedBodyChunkBytes(
            .{},
            default_paced_response_body_chunk_bytes,
        ).paced_body_chunk_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 4096),
        resolvePacedBodyChunkBytes(
            .{ .paced_body_chunk_bytes = 4096 },
            default_paced_response_body_chunk_bytes,
        ).paced_body_chunk_bytes,
    );
}

test "HTTP/3 handshake options reject invalid SETTINGS before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const unreachable_server = net.IpAddress{ .ip4 = .loopback(443) };
    const invalid_settings = http3.Settings{
        .qpack_max_table_capacity = @as(u64, quic.varint.max_value) + 1,
    };

    try std.testing.expectError(
        error.InvalidSetting,
        validateHandshakeSessionOptions(.{
            .max_post_handshake_crypto_bytes = 3,
        }),
    );

    try std.testing.expectError(
        error.InvalidSetting,
        HandshakeServer.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{},
            .{
                .handshake = .{ .local_connection_id = "server" },
                .session = .{ .local_settings = invalid_settings },
            },
        ),
    );
    try std.testing.expectError(
        error.InvalidSetting,
        HandshakeClient.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            unreachable_server,
            .{},
            .{
                .handshake = .{
                    .original_destination_connection_id = "12345678",
                    .local_connection_id = "client",
                    .server_name = "localhost",
                },
                .session = .{ .local_settings = invalid_settings },
            },
        ),
    );
    try std.testing.expectError(
        error.QpackDynamicTableUnsupported,
        validateHandshakeSessionOptions(.{
            .local_settings = .{ .qpack_blocked_streams = 2 },
            .max_concurrent_request_streams = 1,
        }),
    );
}

test "HTTP/3 handshake server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe2} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
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
            session.control.local_goaway_id = 0;
            try std.testing.expectError(error.RequestRejected, session.receiveRequest());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe3} ** 32,
        },
    });
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
    try sendConnectionMessage(
        &client.established.connection,
        &client.stream_send_scratch,
        &client.critical_stream_send_scratch,
        0,
        .{ .method = "GET", .path = "/rejected", .authority = "localhost" },
        client.options,
        client.control.settings.peer,
        &client.qpack_encode,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xaa, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xbb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();
    server.control.local_goaway_id = 0;

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            std.testing.expectError(error.RequestRejected, shared.server.receiveRequest()) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    // Send a request without waiting for a response; the server-side receive path
    // should reject it because local GOAWAY(0) says no client request stream is
    // still acceptable.
    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{ .method = "GET", .path = "/rejected", .authority = "localhost" }).write(&encoded, allocator);
    var send_state = quic.stream_state.SendState.init(0);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try send_state.appendFrames(&frames, allocator, encoded.items, encoded.items.len, true);
    try sendProtectedFrames(&client.quic_client.endpoint, client.quic_client.peer, client.config.send_keys, client.config.peer_connection_id, &client.next_packet_number, frames.items, client.config.max_frames_per_packet, &client.protected_send);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected request zero-progress failures preserve retry state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa3, 0x21, 0x22, 0x23 };
    const server_cid = [_]u8{ 0xa4, 0x21, 0x22, 0x23 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa6} ** quic.protection.secret_len,
    );
    const settings: http3.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
    };
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = settings,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        client_address: net.IpAddress,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const expected_ids = [_]u62{ 0, 4 };
            for (expected_ids) |expected_id| {
                var request = try self.server.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    self.server.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqual(expected_id, request.stream_id);
                try self.server.sendResponse(
                    self.client_address,
                    request.stream_id,
                    .{ .status = 204 },
                );
            }
        }
    };

    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();
    var shared = Shared{
        .server = &server,
        .client_address = client.quic_client.address(),
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(error.InvalidHeader, client.sendRequest(.{
        .method = "GET",
        .path = "/invalid-before-send",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "invalid" }},
    }));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(!client.control.settings.sent);

    // Seed the peer limits without marking SETTINGS received: the protected
    // server will send its real control stream with the first response.
    client.control.settings.peer = settings;
    try client.qpack_encode.configurePeerLimits(
        settings.qpack_max_table_capacity,
        settings.qpack_blocked_streams,
    );
    _ = try client.qpack_encode.insertField(
        "x-protected-transaction",
        "reused-value",
    );
    const inserted_before_request = client.qpack_encode.table.insert_count;

    const FailOnCall = struct {
        delegate: std.Io,
        fail_on_call: usize,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == self.fail_on_call) {
                return .{ error.NetworkDown, 0 };
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var failed = FailOnCall{
        .delegate = client.quic_client.endpoint.io,
        .fail_on_call = 3,
    };
    var failed_vtable = failed.delegate.vtable.*;
    failed_vtable.netSend = FailOnCall.netSend;
    client.quic_client.endpoint.io = .{
        .userdata = &failed,
        .vtable = &failed_vtable,
    };
    defer client.quic_client.endpoint.io = failed.delegate;

    const request: http3.Request = .{
        .method = "GET",
        .path = "/protected-transaction",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-protected-transaction",
            .value = "reused-value",
        }},
    };
    try std.testing.expectError(error.NetworkDown, client.sendRequest(request));
    try std.testing.expectEqual(@as(usize, 3), failed.calls);
    try std.testing.expect(client.protected_send.isUsable());
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pendingEncoderInstructions().len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(
        client.qpack_encode.table.insert_count > inserted_before_request,
    );

    client.quic_client.endpoint.io = failed.delegate;
    const aggregate_id = try client.sendRequest(request);
    try std.testing.expectEqual(@as(u62, 0), aggregate_id);
    var aggregate_response = try client.receiveResponseWithTimeout(
        aggregate_id,
        .fromSeconds(2),
    );
    defer aggregate_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), aggregate_response.response.status);

    failed.calls = 0;
    failed.fail_on_call = 1;
    client.quic_client.endpoint.io = .{
        .userdata = &failed,
        .vtable = &failed_vtable,
    };
    try std.testing.expectError(
        error.NetworkDown,
        client.startRequest(request, 0),
    );
    try std.testing.expectEqual(@as(usize, 1), failed.calls);
    try std.testing.expect(client.protected_send.isUsable());
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(client.outbound_bodies.find(4) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );

    client.quic_client.endpoint.io = failed.delegate;
    const streaming_id = try client.startRequest(request, 0);
    try std.testing.expectEqual(@as(u62, 4), streaming_id);
    var streaming_response = try client.receiveResponseWithTimeout(
        streaming_id,
        .fromSeconds(2),
    );
    defer streaming_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), streaming_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 protected runtime rejects server-initiated bidirectional message streams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc1, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xc2, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xc2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    const invalid = [_]quic.Frame{.{
        .stream = .{
            .stream_id = 1, // server-initiated bidirectional: invalid for HTTP/3 messages.
            .data = "not a request stream",
            .fin = true,
        },
    }};
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &invalid,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    try std.testing.expectError(error.StreamCreationError, server.receiveRequest());
}

test "HTTP/3 handshake runtime establishes QUIC and exchanges request response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        },
        .session = .{ .local_settings = .{ .h3_datagram = true }, .max_stream_frame_data = 7 },
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
            try std.testing.expectEqualStrings("h3", session.established.alpn);

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3-handshake", request.request.path);
            try std.testing.expectEqualStrings("split by handshake runtime", request.request.body);
            try std.testing.expect(session.control.settings.received);
            try std.testing.expectEqual(@as(u64, 6), session.control.settings.peer.webtransport_max_sessions);
            try std.testing.expectEqual(@as(?u64, client_control_stream_id), session.control.peer_control_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), session.control.peer_qpack_encoder_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_decoder_stream_id), session.control.peer_qpack_decoder_stream_id);
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            const pending_sections =
                session.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseWithDeadline(
                    request.stream_id,
                    .{ .status = 204 },
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
            try std.testing.expectEqual(
                pending_sections,
                session.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
            );
            try session.sendResponseWithTimeout(
                request.stream_id,
                .{
                    .status = 200,
                    .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                    .body = "handshake pong",
                },
                .fromSeconds(2),
            );
            try std.testing.expect(session.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        },
        .session = .{ .local_settings = .{ .webtransport_max_sessions = 6 }, .max_stream_frame_data = 7 },
    });
    defer client.deinit();
    try std.testing.expectEqualStrings("h3", client.established.alpn);

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3-handshake",
        .authority = "localhost",
        .body = "split by handshake runtime",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("handshake pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(?u64, server_control_stream_id), client.control.peer_control_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_encoder_stream_id), client.control.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_decoder_stream_id), client.control.peer_qpack_decoder_stream_id);
}

test "HTTP/3 handshake client sends priority update before request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94 };
    const client_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const server_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
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
                .random = [_]u8{0x9f} ** 32,
                .x25519_secret_key = [_]u8{0xa0} ** 32,
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
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(1),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            // Admission consumes the one-shot control-stream hint into the
            // active request lifecycle. Validate the effective scheduler
            // priority rather than the retired compatibility view.
            const priority = session.request_lifecycle.priority(
                request.stream_id,
            );
            try std.testing.expectEqual(
                @as(u3, 2),
                priority.urgency,
            );
            try std.testing.expect(priority.incremental);
            try std.testing.expect(
                session.control.requestPriorityUpdate(request.stream_id) ==
                    null,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
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
                .random = [_]u8{0x9d} ** 32,
                .x25519_secret_key = [_]u8{0x9e} ** 32,
            },
        },
    );
    defer client.deinit();

    const packet_number = client.established.connection.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendPriorityUpdateWithDeadline(
            0,
            .{ .urgency = 1 },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try client.sendPriorityUpdateWithTimeout(0, .{
        .urgency = 2,
        .incremental = true,
    }, .fromSeconds(2));
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/prioritized",
        .authority = "localhost",
    });
    var response = client.receiveResponseWithTimeout(
        stream_id,
        .fromSeconds(3),
    ) catch |err| {
        thread.join();
        joined = true;
        if (shared.err) |server_err| return server_err;
        return err;
    };
    defer response.deinit(allocator);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client advertises and cancels server push IDs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4 };
    const client_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const server_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
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
                .random = [_]u8{0xdf} ** 32,
                .x25519_secret_key = [_]u8{0xe0} ** 32,
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
            while (session.control.peer_max_push_id != 8 or
                !session.control.pushCancelled(7) or
                !session.control.pushCancelled(3))
            {
                var packet = try session.established.connection.receivePacket();
                defer packet.deinit(
                    session.established.connection.endpoint.allocator,
                );
                for (packet.frames) |frame| {
                    if (frame != .stream) continue;
                    if (try applyControlStreamFrameForRoleWithPushes(
                        &session.control,
                        session.established.connection.endpoint.allocator,
                        frame.stream,
                        .server,
                        .{ .slice = &.{ 7, 3 } },
                        null,
                        null,
                    )) {
                        try configureQpackEncoderFromPeerSettings(
                            session.control,
                            &session.qpack_encode,
                        );
                    }
                }
            }
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
                .random = [_]u8{0xdd} ** 32,
                .x25519_secret_key = [_]u8{0xde} ** 32,
            },
        },
    );
    defer client.deinit();

    const packet_number = client.established.connection.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendMaxPushIdWithDeadline(
            4,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try std.testing.expectEqual(@as(?u64, null), client.control.local_max_push_id);
    try client.sendMaxPushIdWithTimeout(4, .fromSeconds(2));
    try client.sendMaxPushIdWithTimeout(8, .fromSeconds(2));
    try std.testing.expectError(
        error.MaxPushIdReduced,
        client.sendMaxPushId(7),
    );
    try std.testing.expectError(error.PushIdExceeded, client.cancelPush(9));
    try client.push_streams.registerPromise(7, 0);
    try client.push_streams.registerPromise(3, 0);
    try client.cancelPushWithTimeout(7, .fromSeconds(2));
    try client.cancelPushWithTimeout(3, .fromSeconds(2));
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client streams promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Observation = struct {
        push_ids: [2]u64 = undefined,
        request_stream_ids: [2]u62 = undefined,
        stream_ids: [2]u62 = undefined,
        statuses: [2]u16 = undefined,
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            push_id: u64,
            request_stream_id: u62,
            stream_id: u62,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count >= self.statuses.len) return;
            self.push_ids[self.count] = push_id;
            self.request_stream_ids[self.count] = request_stream_id;
            self.stream_ids[self.count] = stream_id;
            self.statuses[self.count] = response.status;
            self.count += 1;
        }
    };
    const original_dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const client_cid = [_]u8{ 0xe9, 0xea, 0xeb, 0xec };
    const server_cid = [_]u8{ 0xed, 0xee, 0xef, 0xf0 };
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
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
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
            while (session.control.peer_max_push_id != 1) {
                try session.receiveRequestPacket();
            }
            const push = ServerPush{
                .push_id = 1,
                .request = .{
                    .method = "GET",
                    .path = "/handshake.css",
                    .authority = "localhost",
                },
                .informational = &.{
                    .{ .status = 103 },
                    .{ .status = 102 },
                },
                .response = .{
                    .status = 200,
                    .body = "handshake-asset",
                },
            };
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            const next_push_stream_id = session.next_push_stream_id;
            const pending_sections =
                session.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseWithPushAndDeadline(
                    request.stream_id,
                    .{ .status = 204 },
                    push,
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
            try std.testing.expectEqual(
                next_push_stream_id,
                session.next_push_stream_id,
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                session.promised_push_ids.rangeCount(),
            );
            try std.testing.expectEqual(
                pending_sections,
                session.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
            );
            const push_stream_id = try session.sendResponseWithPushAndTimeout(
                request.stream_id,
                .{ .status = 204 },
                push,
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                first_server_push_stream_id,
                push_stream_id,
            );
            try std.testing.expect(
                session.push_send_scratch.parent.capacity != 0,
            );
            try std.testing.expect(
                session.push_send_scratch.pushed.capacity != 0,
            );
            try std.testing.expect(
                session.push_send_scratch.frames.capacity != 0,
            );
            while (!session.established.connection
                .localStreamClosed(push_stream_id))
            {
                try session.pollControlWithTimeout(.fromSeconds(2));
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var thread_joined = false;
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
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
        },
    );
    defer client.deinit();
    defer if (!thread_joined) thread.join();
    try client.sendMaxPushId(1);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "localhost",
    });
    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    var observation: Observation = .{};
    var pushed = try client.receivePushWithInformational(.{
        .context = &observation,
        .on_response = Observation.observe,
    });
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqual(request_stream_id, pushed.request_stream_id);
    try std.testing.expectEqual(@as(u62, 15), pushed.stream_id);
    try std.testing.expectEqualStrings(
        "handshake-asset",
        pushed.response.body,
    );
    try std.testing.expect(client.established.connection
        .peerStreamClosed(pushed.stream_id));
    try std.testing.expect(client.push_streams.hasPromise(pushed.push_id));
    try std.testing.expectEqual(@as(usize, 2), observation.count);
    for (observation.statuses, 0..) |status, index| {
        try std.testing.expectEqual(@as(u64, 1), observation.push_ids[index]);
        try std.testing.expectEqual(
            request_stream_id,
            observation.request_stream_ids[index],
        );
        try std.testing.expectEqual(@as(u62, 15), observation.stream_ids[index]);
        try std.testing.expectEqual(
            if (index == 0) @as(u16, 103) else 102,
            status,
        );
    }
    thread.join();
    thread_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client sends priority update for promised push" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    const server_cid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd1} ** 32,
                .x25519_secret_key = [_]u8{0xd2} ** 32,
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
            try session.promised_push_ids.prepareInsertValue(
                session.established.connection.endpoint.allocator,
                1,
            );
            session.promised_push_ids.insertAssumeCapacity(1);
            while (session.control.pushPriorityUpdate(1) == null) {
                try session.receiveRequestPacket();
            }
            const priority =
                session.control.pushPriorityUpdate(1).?.priority();
            try std.testing.expectEqual(@as(u3, 4), priority.urgency);
            try std.testing.expect(priority.incremental);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(1);
    try client.push_streams.registerPromise(1, 0);
    const packet_number = client.established.connection.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendPushPriorityUpdateWithDeadline(
            1,
            .{ .urgency = 2 },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try client.sendPushPriorityUpdateWithTimeout(1, .{
        .urgency = 4,
        .incremental = true,
    }, .fromSeconds(2));
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client retains interleaved responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Observation = struct {
        stream_ids: [4]u62 = undefined,
        statuses: [4]u16 = undefined,
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            stream_id: u62,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count >= self.statuses.len) return;
            self.stream_ids[self.count] = stream_id;
            self.statuses[self.count] = response.status;
            self.count += 1;
        }
    };

    const original_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
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
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
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
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponseWithInformational(
                second.stream_id,
                &.{ .{ .status = 103 }, .{ .status = 102 } },
                .{ .status = 200, .body = "second-response" },
            );
            try session.sendResponseWithInformational(
                first.stream_id,
                &.{ .{ .status = 103 }, .{ .status = 102 } },
                .{ .status = 200, .body = "first-response" },
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
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
        },
    );
    defer client.deinit();

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    var observation: Observation = .{};
    const observer: MultiplexedInformationalObserver = .{
        .context = &observation,
        .on_response = Observation.observe,
    };
    var first_event = try client.receiveNextResponseWithInformational(observer);
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(
        second_id,
        first_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "second-response",
        first_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.request_lifecycle.count(),
    );
    var second_event = try client.receiveNextResponseWithInformational(observer);
    defer second_event.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        first_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "first-response",
        second_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.count(),
    );
    try std.testing.expectEqual(@as(usize, 4), observation.count);
    for (observation.statuses, 0..) |status, index| {
        try std.testing.expectEqual(
            if (index < 2) second_id else first_id,
            observation.stream_ids[index],
        );
        try std.testing.expectEqual(
            if (index % 2 == 0) @as(u16, 103) else 102,
            status,
        );
    }
}

test "HTTP/3 handshake client response deadline preserves progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x3d, 0x3e, 0x3f, 0x40 };
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
            .random = [_]u8{0x43} ** 32,
            .x25519_secret_key = [_]u8{0x44} ** 32,
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
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.Io.sleep(
                session.established.connection.endpoint.io,
                .fromMilliseconds(80),
                .awake,
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "after-timeout",
            });
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
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x41} ** 32,
            .x25519_secret_key = [_]u8{0x42} ** 32,
        } },
    );
    defer client.deinit();
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/deadline",
        .authority = "localhost",
    });
    try std.testing.expectError(
        error.Timeout,
        client.receiveResponseWithTimeout(
            stream_id,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(client.request_lifecycle.contains(stream_id));

    var saw_head = false;
    var saw_finished = false;
    var body: [32]u8 = undefined;
    var body_len: usize = 0;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!saw_finished) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| {
                try std.testing.expect(head == .response);
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                saw_head = true;
            },
            .data_available => {
                const count = try client.readResponseData(
                    stream_id,
                    body[body_len..],
                );
                body_len += count;
            },
            .finished => saw_finished = true,
            .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expectEqualStrings("after-timeout", body[0..body_len]);
    try std.testing.expect(!client.request_lifecycle.contains(stream_id));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client next-response deadlines preserve progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x63} ** 32,
            .x25519_secret_key = [_]u8{0x64} ** 32,
        } },
    );
    defer server.deinit();

    const aggregate_body = "aggregate-next";
    const streaming_body = "streaming-next";
    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        aggregate_head_sent: std.Io.Event = .unset,
        aggregate_timed_out: std.Io.Event = .unset,
        streaming_head_sent: std.Io.Event = .unset,
        streaming_timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.aggregate_head_sent.set(self.io);
                self.aggregate_timed_out.set(self.io);
                self.streaming_head_sent.set(self.io);
                self.streaming_timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();

            var aggregate = try session.receiveRequest();
            defer aggregate.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                aggregate.stream_id,
                .{ .status = 200 },
                aggregate_body.len,
            );
            self.aggregate_head_sent.set(self.io);
            try self.aggregate_timed_out.wait(self.io);
            try session.sendResponseBody(
                aggregate.stream_id,
                aggregate_body,
                true,
            );

            var streaming = try session.receiveRequest();
            defer streaming.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                streaming.stream_id,
                .{ .status = 200 },
                streaming_body.len,
            );
            self.streaming_head_sent.set(self.io);
            try self.streaming_timed_out.wait(self.io);
            try session.sendResponseBody(
                streaming.stream_id,
                streaming_body,
                true,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
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
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x61} ** 32,
            .x25519_secret_key = [_]u8{0x62} ** 32,
        } },
    );
    defer client.deinit();

    const aggregate_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/aggregate-next-deadline",
        .authority = "localhost",
    });
    try shared.aggregate_head_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveNextResponseWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_lifecycle.contains(aggregate_id));
    try std.testing.expect(!client.response_streams.isEmpty());
    shared.aggregate_timed_out.set(io);

    var aggregate_event = try client.receiveNextResponseWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer aggregate_event.deinit(allocator);
    try std.testing.expect(aggregate_event == .response);
    try std.testing.expectEqual(
        aggregate_id,
        aggregate_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        aggregate_body,
        aggregate_event.response.value.response.body,
    );
    try std.testing.expect(!client.request_lifecycle.contains(aggregate_id));

    const streaming_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/streaming-next-deadline",
        .authority = "localhost",
    });
    try shared.streaming_head_sent.wait(io);
    var head = try client.receiveNextResponseEventWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expectEqual(streaming_id, head.message.stream_id);
    try std.testing.expect(head.message.value == .head);

    try std.testing.expectError(
        error.Timeout,
        client.receiveNextResponseEventWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_lifecycle.contains(streaming_id));
    try std.testing.expect(client.streaming_responses.find(streaming_id) != null);
    shared.streaming_timed_out.set(io);

    var body: [32]u8 = undefined;
    var body_len: usize = 0;
    var finished = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!finished) {
        var event = try client.receiveNextResponseEventWithDeadline(deadline);
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        try std.testing.expectEqual(streaming_id, event.message.stream_id);
        switch (event.message.value) {
            .data_available => {
                body_len += try client.readResponseData(
                    streaming_id,
                    body[body_len..],
                );
            },
            .finished => finished = true,
            .head, .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualStrings(streaming_body, body[0..body_len]);
    try std.testing.expect(!client.request_lifecycle.contains(streaming_id));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client push deadlines preserve progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
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
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        } },
    );
    defer server.deinit();

    const aggregate_body = "aggregate-push-after-timeout";
    const streaming_body = "streaming-push-after-timeout";
    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        aggregate_prefix_sent: std.Io.Event = .unset,
        aggregate_timed_out: std.Io.Event = .unset,
        streaming_prefix_sent: std.Io.Event = .unset,
        streaming_timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.aggregate_prefix_sent.set(self.io);
                self.aggregate_timed_out.set(self.io);
                self.streaming_prefix_sent.set(self.io);
                self.streaming_timed_out.set(self.io);
            };
        }

        fn sendSplitPush(
            self: *@This(),
            session: *HandshakeServerSession,
            request_stream_id: u62,
            push_id: u64,
            push_stream_id: u62,
            path: []const u8,
            body: []const u8,
            body_prefix_len: usize,
            prefix_sent: *std.Io.Event,
            timed_out: *std.Io.Event,
        ) !void {
            var parent: std.ArrayList(u8) = .empty;
            defer parent.deinit(allocator);
            var pushed: std.ArrayList(u8) = .empty;
            defer pushed.deinit(allocator);
            try encodePushMessages(
                allocator,
                session.control.settings.peer,
                request_stream_id,
                .{ .status = 204 },
                push_stream_id,
                .{
                    .push_id = push_id,
                    .request = .{
                        .method = "GET",
                        .path = path,
                        .authority = "localhost",
                    },
                    .response = .{
                        .status = 200,
                        .body = body,
                    },
                },
                &session.qpack_encode,
                &parent,
                &pushed,
            );
            try sendConnectionQpackEncoderInstructions(
                &session.established.connection,
                &session.critical_stream_send_scratch,
                &session.qpack_encode,
                &session.qpack_encoder_send,
                &session.qpack_encoder_prefix_sent,
                session.options,
            );
            const split = pushed.items.len - body.len + body_prefix_len;
            const prefix_frames = [_]quic.Frame{
                .{ .stream = .{
                    .stream_id = request_stream_id,
                    .data = parent.items,
                    .fin = true,
                } },
                .{ .stream = .{
                    .stream_id = push_stream_id,
                    .data = pushed.items[0..split],
                    .fin = false,
                } },
            };
            try sendConnectionFrames(
                &session.established.connection,
                &prefix_frames,
                session.options.max_frames_per_packet,
            );
            prefix_sent.set(self.io);
            try timed_out.wait(self.io);
            try sendConnectionFrames(
                &session.established.connection,
                &.{.{ .stream = .{
                    .stream_id = push_stream_id,
                    .offset = split,
                    .data = pushed.items[split..],
                    .fin = true,
                } }},
                session.options.max_frames_per_packet,
            );
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(allocator);
            while (session.control.peer_max_push_id != 2) {
                try session.receiveRequestPacket();
            }
            try self.sendSplitPush(
                &session,
                first.stream_id,
                1,
                first_server_push_stream_id,
                "/aggregate-push",
                aggregate_body,
                aggregate_body.len / 2,
                &self.aggregate_prefix_sent,
                &self.aggregate_timed_out,
            );

            var second = try session.receiveRequest();
            defer second.deinit(allocator);
            try self.sendSplitPush(
                &session,
                second.stream_id,
                2,
                first_server_push_stream_id + 4,
                "/streaming-push",
                streaming_body,
                0,
                &self.streaming_prefix_sent,
                &self.streaming_timed_out,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        // Never hide a client-side assertion behind a server thread waiting
        // for the continuation gates below.
        shared.aggregate_timed_out.set(io);
        shared.streaming_timed_out.set(io);
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
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
        } },
    );
    defer client.deinit();
    try client.sendMaxPushId(2);

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first-push",
        .authority = "localhost",
    });
    try shared.aggregate_prefix_sent.wait(io);
    while (true) {
        const event = try client.receiveResponseEvent(first_id);
        if (event) |value| {
            var owned = value;
            defer owned.deinit(allocator);
            if (owned == .push_promise) break;
        }
    }
    try std.testing.expectError(
        error.Timeout,
        client.receivePushWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(@as(?u64, 1), client.push_aggregate.push_id);
    try std.testing.expect(client.push_aggregate.head != null);
    try std.testing.expectEqualStrings(
        aggregate_body[0 .. aggregate_body.len / 2],
        client.push_aggregate.body.items,
    );
    shared.aggregate_timed_out.set(io);
    var aggregate = try client.receivePushWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer aggregate.deinit(allocator);
    try std.testing.expectEqualStrings(aggregate_body, aggregate.response.body);

    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second-push",
        .authority = "localhost",
    });
    try shared.streaming_prefix_sent.wait(io);
    while (true) {
        const event = try client.receiveResponseEvent(second_id);
        if (event) |value| {
            var owned = value;
            defer owned.deinit(allocator);
            if (owned == .push_promise) break;
        }
    }
    var push_head = try client.receivePushEventWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer push_head.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), push_head.push_id);
    try std.testing.expect(push_head.value == .head);
    try std.testing.expectError(
        error.Timeout,
        client.receivePushEventWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.push_streams.findByPushId(2) != null);
    shared.streaming_timed_out.set(io);

    var skipped_body_len: usize = 0;
    var finished = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!finished) {
        var event = try client.receivePushEventWithDeadline(deadline);
        defer event.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 2), event.push_id);
        switch (event.value) {
            .data_available => {
                skipped_body_len += try client.skipPushData(2);
            },
            .finished => finished = true,
            .head, .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(streaming_body.len, skipped_body_len);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client drains GRO response batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc };
    const client_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = true,
                },
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
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
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
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

            var first_bytes: std.ArrayList(u8) = .empty;
            defer first_bytes.deinit(
                session.established.connection.endpoint.allocator,
            );
            try (http3.Response{
                .status = 200,
                .body = "response-one",
            }).write(
                &first_bytes,
                session.established.connection.endpoint.allocator,
            );
            var second_bytes: std.ArrayList(u8) = .empty;
            defer second_bytes.deinit(
                session.established.connection.endpoint.allocator,
            );
            try (http3.Response{
                .status = 200,
                .body = "response-two",
            }).write(
                &second_bytes,
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(
                first_bytes.items.len,
                second_bytes.items.len,
            );
            const second_frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = second.stream_id,
                .data = second_bytes.items,
                .fin = true,
            } }};
            const first_frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = first.stream_id,
                .data = first_bytes.items,
                .fin = true,
            } }};
            const packets = [_][]const quic.Frame{
                &second_frames,
                &first_frames,
            };
            try session.established.connection.sendMany(&packets);
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
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
        },
    );
    defer client.deinit();
    if (!client.endpoint.groReceiveEnabled()) {
        thread.join();
        if (shared.err) |err| return err;
        return error.SkipZigTest;
    }

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    });
    // Force the cursor through the timer-aware GRO branch rather than the
    // no-deadline shortcut. The server's two response packets should still be
    // retained as one owning batch behind the first application event.
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    client.established.connection.ack_delay_start_ns = @intCast(now);
    client.established.connection.ack_delay_deadline_ns =
        @intCast(now + std.time.ns_per_s);
    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        second_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "response-two",
        second_event.response.value.response.body,
    );
    try std.testing.expect(client.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.receive_packets.batch.?.remaining(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.response_streams.count(),
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(first_id, first_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "response-one",
        first_event.response.value.response.body,
    );
}

test "HTTP/3 handshake client batches request DATA across streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
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
            var saw_first = false;
            var saw_second = false;
            var first_stream_id: ?u62 = null;
            var second_stream_id: ?u62 = null;
            for (0..2) |_| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/batch-first",
                )) {
                    try std.testing.expectEqualStrings(
                        "first-body",
                        request.request.body,
                    );
                    saw_first = true;
                    first_stream_id = request.stream_id;
                } else if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/batch-second",
                )) {
                    try std.testing.expectEqualStrings(
                        "second-body",
                        request.request.body,
                    );
                    saw_second = true;
                    second_stream_id = request.stream_id;
                } else {
                    return error.TestUnexpectedResult;
                }
            }
            try std.testing.expect(saw_first);
            try std.testing.expect(saw_second);
            try session.startResponse(
                first_stream_id.?,
                .{ .status = 200 },
                "first-response".len,
            );
            try session.startResponse(
                second_stream_id.?,
                .{ .status = 200 },
                "second-response".len,
            );
            const chunks = [_]BodyChunk{
                .{
                    .stream_id = first_stream_id.?,
                    .data = "first-response",
                    .fin = true,
                },
                .{
                    .stream_id = second_stream_id.?,
                    .data = "second-response",
                    .fin = true,
                },
            };
            var committed: usize = 99;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyBatchPacedWithTimeout(
                    &chunks,
                    &committed,
                    .zero,
                ),
            );
            try std.testing.expectEqual(@as(usize, 0), committed);
            committed = 99;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyBatchPacedWithDeadline(
                    &chunks,
                    &committed,
                    .fromNow(
                        session.connectionIo(),
                        .{ .raw = .fromSeconds(1), .clock = .real },
                    ),
                ),
            );
            try std.testing.expectEqual(@as(usize, 0), committed);
            try session.sendResponseBodyBatchPacedWithDeadline(
                &chunks,
                &committed,
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );
            try std.testing.expectEqual(@as(usize, 2), committed);
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = true,
                },
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
        },
    );
    defer client.deinit();

    const first = try client.startRequest(.{
        .method = "POST",
        .path = "/batch-first",
        .authority = "localhost",
    }, "first-body".len);
    const second = try client.startRequest(.{
        .method = "POST",
        .path = "/batch-second",
        .authority = "localhost",
    }, "second-body".len);
    const chunks = [_]BodyChunk{
        .{ .stream_id = first, .data = "first-body", .fin = true },
        .{ .stream_id = second, .data = "second-body", .fin = true },
    };
    const first_offset = client.outbound_bodies.find(first).?.send.next_offset;
    const second_offset = client.outbound_bodies.find(second).?.send.next_offset;
    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithTimeout(
            &chunks,
            &committed,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(
        first_offset,
        client.outbound_bodies.find(first).?.send.next_offset,
    );
    try std.testing.expectEqual(
        second_offset,
        client.outbound_bodies.find(second).?.send.next_offset,
    );
    committed = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithDeadline(
            &chunks,
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendRequestBodyBatchPaced(&.{
            .{ .stream_id = first, .data = "first-body", .fin = true },
            .{ .stream_id = first, .data = "first-body", .fin = true },
        }),
    );
    const FixedPacingIo = struct {
        delegate: std.Io,
        now_ns: i96,
        sleep_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            return error.Canceled;
        }
    };
    var fixed_io = FixedPacingIo{
        .delegate = client.endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = client.endpoint.io.vtable.*;
    fixed_vtable.now = FixedPacingIo.now;
    fixed_vtable.sleep = FixedPacingIo.sleep;
    client.endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns),
    );
    committed = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithDeadline(
            &chunks,
            &committed,
            .fromNow(
                client.connectionIo(),
                .{ .raw = .fromNanoseconds(1), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    const pacing = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        pacing.kind,
    );
    fixed_io.now_ns = @intCast(pacing.deadline_ns);
    _ = (try client.established.connection.serviceNextTimerAt(
        pacing.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    client.endpoint.io = fixed_io.delegate;
    const PartialBatchSend = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.calls += 1;
            const prefix_len = @min(@as(usize, 1), messages.len);
            if (prefix_len != 0) {
                const send_error, const sent_count = self.delegate.vtable.netSend(
                    self.delegate.userdata,
                    socket_handle,
                    messages[0..prefix_len],
                    flags,
                );
                if (send_error != null or sent_count != prefix_len) {
                    return .{ send_error, sent_count };
                }
            }
            return .{ error.NetworkDown, prefix_len };
        }
    };
    var partial = PartialBatchSend{ .delegate = client.endpoint.io };
    var partial_vtable = client.endpoint.io.vtable.*;
    partial_vtable.netSend = PartialBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &partial,
        .vtable = &partial_vtable,
    };
    defer client.endpoint.io = partial.delegate;
    committed = 99;
    try std.testing.expectError(
        error.NetworkDown,
        client.sendRequestBodyBatchPacedWithDeadline(
            &chunks,
            &committed,
            .fromNow(
                client.connectionIo(),
                .{ .raw = .fromSeconds(2), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expect(client.outbound_bodies.find(first) == null);
    try std.testing.expectEqual(
        second_offset,
        client.outbound_bodies.find(second).?.send.next_offset,
    );
    client.endpoint.io = partial.delegate;
    committed = 99;
    try client.sendRequestBodyBatchPacedWithDeadline(
        chunks[1..],
        &committed,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    for (0..2) |_| {
        var event = try client.receiveNextResponse();
        defer event.deinit(allocator);
        try std.testing.expect(event == .response);
        try std.testing.expectEqual(@as(u16, 200), event.response.value.response.status);
        if (event.response.stream_id == first) {
            try std.testing.expectEqualStrings(
                "first-response",
                event.response.value.response.body,
            );
        } else if (event.response.stream_id == second) {
            try std.testing.expectEqualStrings(
                "second-response",
                event.response.value.response.body,
            );
        } else {
            return error.TestUnexpectedResult;
        }
    }
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 detached progress timeout validates budget before state" {
    var server: HandshakeServerSession = undefined;
    var committed_chunks: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        server.sendResponseBodyBatchPacedWithTimeout(
            &.{},
            &committed_chunks,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed_chunks);
    var committed_bytes: [0]usize = .{};
    try std.testing.expectError(
        error.Timeout,
        server.sendResponseBodiesPacedWithTimeout(
            &.{},
            &committed_bytes,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveDetachedRequestProgressWithTimeout(0, .zero),
    );

    var client: HandshakeClient = undefined;
    committed_chunks = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithTimeout(
            &.{},
            &committed_chunks,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed_chunks);
    try std.testing.expectError(
        error.Timeout,
        client.receiveDetachedResponseProgressWithTimeout(0, .zero),
    );
}

test "HTTP/3 handshake body parts deadline resumes exact slice prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            const send_error, const sent_count = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (sent_count != 0) self.now_ns += std.time.ns_per_s;
            return .{ send_error, sent_count };
        }
    };

    const original_dcid =
        [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    const server_cid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90 };
    const session_options: HandshakeSessionOptions = .{
        .max_frames_per_packet = 8,
        .max_stream_frame_data = 32,
        .paced_body_chunk_bytes = 3,
        .enable_data_prefix_fast_path = true,
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
            },
            .session = session_options,
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
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "abcdefghi",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            try session.startResponse(
                request.stream_id,
                .{ .status = 200 },
                "jklmnopqr".len,
            );
            const response_before =
                session.outbound_bodies.find(request.stream_id).?.*;
            var progress: BodyWriteProgress = .{
                .committed_bytes = 99,
                .fin_committed = true,
            };
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "jk", "lmno", "pqr" },
                    true,
                    &progress,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            const response_after =
                session.outbound_bodies.find(request.stream_id).?.*;
            try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);
            try std.testing.expectEqual(
                response_before.written,
                response_after.written,
            );
            try std.testing.expectEqual(
                response_before.send.next_offset,
                response_after.send.next_offset,
            );
            const response_packet_number =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.InvalidContentLength,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "too-", "many-bytes" },
                    true,
                    &progress,
                    .fromNow(
                        session.connectionIo(),
                        .{ .raw = .fromSeconds(2), .clock = .awake },
                    ),
                ),
            );
            try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
            try std.testing.expectEqual(
                response_packet_number,
                session.established.connection.next_packet_number,
            );

            var timed = DeadlineAfterSendIo{
                .delegate = session.established.connection.endpoint.io,
                .now_ns = std.Io.Clock.awake.now(
                    session.established.connection.endpoint.io,
                ).nanoseconds,
            };
            var timed_vtable = timed.delegate.vtable.*;
            timed_vtable.now = DeadlineAfterSendIo.now;
            timed_vtable.netSend = DeadlineAfterSendIo.netSend;
            session.established.connection.endpoint.io = .{
                .userdata = &timed,
                .vtable = &timed_vtable,
            };
            defer session.established.connection.endpoint.io = timed.delegate;

            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "jk", "lmno", "pqr" },
                    true,
                    &progress,
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(timed.now_ns + 1),
                    },
                ),
            );
            try std.testing.expectEqual(@as(usize, 3), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);
            try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

            session.established.connection.endpoint.io = timed.delegate;
            try session.sendResponseBodyPartsPacedWithDeadline(
                request.stream_id,
                &.{ "mno", "pqr" },
                false,
                &progress,
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );
            try std.testing.expectEqual(@as(usize, 6), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);

            const trailer_packet_number =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                session.finishResponseTrailersPacedWithDeadline(
                    request.stream_id,
                    &.{.{ .name = "x-response-finish", .value = "ok" }},
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                trailer_packet_number,
                session.established.connection.next_packet_number,
            );
            const trailer_now = std.Io.Clock.awake.now(
                session.connectionIo(),
            ).nanoseconds;
            quic.one_rtt.testing.exhaustPacingAt(
                &session.established.connection,
                @intCast(trailer_now),
            );
            try std.testing.expectError(
                error.Timeout,
                session.finishResponseTrailersPacedWithDeadline(
                    request.stream_id,
                    &.{.{ .name = "x-response-finish", .value = "ok" }},
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(trailer_now + 1),
                    },
                ),
            );
            try std.testing.expectEqual(
                trailer_packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expect(
                session.outbound_bodies.find(request.stream_id) != null,
            );
            quic.one_rtt.testing.setPacingBudgetAt(
                &session.established.connection,
                session.established.connection.currentSendDatagramSize(),
                @intCast(trailer_now),
            );
            try session.finishResponseTrailersPacedWithDeadline(
                request.stream_id,
                &.{.{ .name = "x-response-finish", .value = "ok" }},
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = true,
                },
                .random = [_]u8{0x93} ** 32,
                .x25519_secret_key = [_]u8{0x94} ** 32,
            },
            .session = session_options,
        },
    );
    defer client.deinit();
    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/parts-deadline",
            .authority = "localhost",
        },
        "abcdefghi".len,
    );
    const before = client.outbound_bodies.find(stream_id).?.*;
    var progress: BodyWriteProgress = .{
        .committed_bytes = 99,
        .fin_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithTimeout(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    const after = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(before.written, after.written);
    try std.testing.expectEqual(before.send.next_offset, after.send.next_offset);
    const request_packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(
        error.InvalidContentLength,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "too-", "many-bytes" },
            true,
            &progress,
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expectEqual(
        request_packet_number,
        client.established.connection.next_packet_number,
    );

    var timed = DeadlineAfterSendIo{
        .delegate = client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(client.endpoint.io).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.endpoint.io = .{ .userdata = &timed, .vtable = &timed_vtable };
    defer client.endpoint.io = timed.delegate;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

    client.endpoint.io = timed.delegate;
    try client.sendRequestBodyPartsPacedWithDeadline(
        stream_id,
        &.{ "def", "ghi" },
        false,
        &progress,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 6), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);

    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithTimeout(
            stream_id,
            &.{.{ .name = "x-request-finish", .value = "ok" }},
            .zero,
        ),
    );
    const trailer_packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithDeadline(
            stream_id,
            &.{.{ .name = "x-request-finish", .value = "ok" }},
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        trailer_packet_number,
        client.established.connection.next_packet_number,
    );
    const trailer_now = std.Io.Clock.awake.now(io).nanoseconds;
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(trailer_now),
    );
    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithDeadline(
            stream_id,
            &.{.{ .name = "x-request-finish", .value = "ok" }},
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(trailer_now + 1),
            },
        ),
    );
    try std.testing.expectEqual(
        trailer_packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expect(client.outbound_bodies.find(stream_id) != null);
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.established.connection,
        client.established.connection.currentSendDatagramSize(),
        @intCast(trailer_now),
    );
    try client.finishRequestTrailersPacedWithDeadline(
        stream_id,
        &.{.{ .name = "x-request-finish", .value = "ok" }},
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );

    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("jklmnopqr", response.response.body);
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake runtime streams request and response DATA chunks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc };
    const client_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
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
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
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
            try std.testing.expectEqualStrings(
                "handshake-request",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            try session.startResponse(
                request.stream_id,
                .{ .status = 200 },
                "handshake-response".len,
            );
            try session.sendResponseBody(
                request.stream_id,
                "handshake-",
                false,
            );
            try session.sendResponseBody(
                request.stream_id,
                "response",
                false,
            );
            try session.finishResponseTrailers(
                request.stream_id,
                &.{.{ .name = "x-response-checksum", .value = "ok" }},
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
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/streaming",
            .authority = "localhost",
        },
        "handshake-request".len,
    );
    try client.sendRequestBody(stream_id, "handshake-", false);
    try client.sendRequestBody(stream_id, "request", false);
    try client.finishRequestTrailers(
        stream_id,
        &.{.{ .name = "x-request-checksum", .value = "ok" }},
    );
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings(
        "handshake-response",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );
}

test "HTTP/3 handshake server streams large request through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 64 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
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
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
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
            var saw_head = false;
            var saw_trailers = false;
            var body_read: usize = 0;
            var checksum: u64 = 0;
            var stream_id: ?u62 = null;
            var read_buf: [113]u8 = undefined;
            while (session.streaming_requests.retainedCount() != 0 or
                !saw_head)
            {
                var event = try session.receiveRequestEvent();
                defer event.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expect(event == .message);
                const message = &event.message;
                if (stream_id) |expected| {
                    try std.testing.expectEqual(expected, message.stream_id);
                } else {
                    stream_id = message.stream_id;
                }
                switch (message.value) {
                    .head => |head| {
                        try std.testing.expect(head == .request);
                        try std.testing.expectEqual(
                            @as(?usize, body_len),
                            head.request.content_length,
                        );
                        saw_head = true;
                    },
                    .push_promise => return error.TestUnexpectedResult,
                    .data_available => {
                        while (true) {
                            const active = session.streaming_requests.find(
                                message.stream_id,
                            ).?;
                            if (!active.reader.hasPendingFrame()) break;
                            const read = try session.readRequestData(
                                message.stream_id,
                                &read_buf,
                            );
                            if (read == 0) break;
                            for (read_buf[0..read]) |byte| checksum +%= byte;
                            body_read += read;
                        }
                        const active = session.streaming_requests.find(
                            message.stream_id,
                        ).?;
                        try std.testing.expect(
                            active.reader.bufferedBytes() <= 512,
                        );
                    },
                    .trailers => |trailers| {
                        try std.testing.expectEqualStrings(
                            "yes",
                            trailers.fields[0].value,
                        );
                        saw_trailers = true;
                    },
                    .finished => {},
                }
            }
            try std.testing.expect(saw_head);
            try std.testing.expect(saw_trailers);
            try std.testing.expectEqual(body_len, body_read);

            var chunk: [400]u8 = undefined;
            var chunk_sum: u64 = 0;
            for (&chunk, 0..) |*byte, index| {
                byte.* = @truncate(index);
                chunk_sum += byte.*;
            }
            var expected = chunk_sum * (body_len / chunk.len);
            for (chunk[0 .. body_len % chunk.len]) |byte| expected += byte;
            try std.testing.expectEqual(expected, checksum);
            try session.sendResponse(stream_id.?, .{ .status = 204 });
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
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/large-handshake-request",
            .authority = "localhost",
        },
        body_len,
    );
    var chunk: [400]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
    var remaining = body_len;
    while (remaining != 0) {
        const count = @min(chunk.len, remaining);
        try client.sendRequestBodyPaced(
            stream_id,
            chunk[0..count],
            false,
        );
        remaining -= count;
    }
    try client.finishRequestTrailersPaced(stream_id, &.{.{
        .name = "x-request-finished",
        .value = "yes",
    }});
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client streams dynamic response through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 1024 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
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
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_frame_data = 480,
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
            for (0..3) |exchange| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/large-handshake-stream",
                    request.request.path,
                );
                if (exchange != 0) {
                    // The first response inserts both repeated fields. Reading
                    // the next request pumps the client's Insert Count
                    // Increment, allowing later response sections to reference
                    // those entries without blocking.
                    try std.testing.expect(
                        session.qpack_encode.known_received_count >= 2,
                    );
                }
                const response: http3.Response = .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "x-stream-kind",
                        .value = "bounded-handshake",
                    }},
                    .trailers = &.{.{
                        .name = "x-stream-finished",
                        .value = "yes",
                    }},
                };
                if (exchange < 2) {
                    var warmup = response;
                    warmup.body = "warmup";
                    try session.sendResponse(request.stream_id, warmup);
                    continue;
                }
                try session.startResponse(
                    request.stream_id,
                    .{
                        .status = response.status,
                        .headers = response.headers,
                    },
                    body_len,
                );
                var chunk: [400]u8 = undefined;
                for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
                var remaining = body_len;
                while (remaining != 0) {
                    const count = @min(chunk.len, remaining);
                    try session.sendResponseBodyPaced(
                        request.stream_id,
                        chunk[0..count],
                        false,
                    );
                    remaining -= count;
                }
                try session.finishResponseTrailersPaced(
                    request.stream_id,
                    response.trailers,
                );
                return;
            }
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
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    for (0..2) |exchange| {
        var warmup = try client.request(.{
            .method = "GET",
            .path = "/large-handshake-stream",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqualStrings("warmup", warmup.response.body);
        if (exchange == 1) {
            try std.testing.expect(
                warmup.response.qpack_section_acknowledgments != 0,
            );
        }
    }

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/large-handshake-stream",
        .authority = "localhost",
    });
    var saw_head = false;
    var saw_trailers = false;
    var body_read: usize = 0;
    var checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (client.request_lifecycle.contains(stream_id)) {
        const event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expectEqual(
                    @as(u16, 200),
                    head.response.status,
                );
                try std.testing.expectEqual(
                    @as(?usize, body_len),
                    head.response.content_length,
                );
                try std.testing.expect(
                    head.response.qpack_section_acknowledgments != 0,
                );
                saw_head = true;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = client.streaming_responses.find(
                        stream_id,
                    ).?;
                    if (!active.reader.hasPendingFrame()) break;
                    const read = try client.readResponseData(
                        stream_id,
                        &read_buf,
                    );
                    if (read == 0) break;
                    for (read_buf[0..read]) |byte| checksum +%= byte;
                    body_read += read;
                }
                const active = client.streaming_responses.find(stream_id).?;
                try std.testing.expect(
                    active.reader.bufferedBytes() <= 512,
                );
            },
            .trailers => |trailers| {
                try std.testing.expectEqualStrings(
                    "yes",
                    trailers.fields[0].value,
                );
                try std.testing.expect(
                    trailers.qpack_section_acknowledgments != 0,
                );
                saw_trailers = true;
            },
            .finished => {},
        }
    }
    thread.join();
    if (shared.err) |err| return err;

    var chunk: [400]u8 = undefined;
    var chunk_checksum: u64 = 0;
    for (&chunk, 0..) |*byte, index| {
        byte.* = @truncate(index);
        chunk_checksum += byte.*;
    }
    var expected_checksum =
        chunk_checksum * (body_len / chunk.len);
    for (chunk[0 .. body_len % chunk.len]) |byte| {
        expected_checksum += byte;
    }
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_trailers);
    try std.testing.expectEqual(body_len, body_read);
    try std.testing.expectEqual(expected_checksum, checksum);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entryCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.count(),
    );
}

test "HTTP/3 handshake runtime reuses acknowledged dynamic QPACK entries" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const server_cid = [_]u8{ 0xac, 0xad, 0xae, 0xaf };

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
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 512 },
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 5,
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
            var encoded_capacity: usize = 0;
            var encoded_ptr: [*]u8 = undefined;
            var critical_capacity: usize = 0;
            var critical_frames_capacity: usize = 0;
            var critical_ptr: [*]u8 = undefined;
            var critical_frames_ptr: [*]quic.Frame = undefined;

            for (0..3) |exchange| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/handshake-dynamic",
                    request.request.path,
                );
                var repeated_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(u8, header.name, "x-handshake-request")) {
                        repeated_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "repeated-request-value",
                    repeated_value orelse return error.TestUnexpectedResult,
                );

                if (exchange == 1) {
                    // The second request carries inserts but remains literal
                    // under SETTINGS_QPACK_BLOCKED_STREAMS=0. Waiting for it
                    // also consumes feedback that unlocks response reuse.
                    try std.testing.expectEqual(
                        @as(usize, 0),
                        request.request.qpack_section_acknowledgments,
                    );
                    try std.testing.expect(
                        session.qpack_decode.table.insert_count != 0,
                    );
                    try std.testing.expect(
                        session.qpack_encode.known_received_count != 0,
                    );
                } else if (exchange == 2) {
                    try std.testing.expect(
                        request.request.qpack_section_acknowledgments != 0,
                    );
                }

                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "x-handshake-response",
                        .value = "repeated-response-value",
                    }},
                    .body = "ok",
                });
                try std.testing.expectEqual(@as(usize, 0), session.stream_send_scratch.frames.capacity);
                if (exchange == 0) {
                    encoded_capacity =
                        session.stream_send_scratch.encoded.capacity;
                    try std.testing.expect(encoded_capacity != 0);
                    encoded_ptr = session.stream_send_scratch.encoded
                        .allocatedSlice().ptr;
                } else {
                    try std.testing.expectEqual(
                        encoded_capacity,
                        session.stream_send_scratch.encoded.capacity,
                    );
                    try std.testing.expectEqual(
                        encoded_ptr,
                        session.stream_send_scratch.encoded
                            .allocatedSlice().ptr,
                    );
                }
                // The second exchange can carry the first dynamic inserts and
                // therefore establishes the steady-state high-water mark.
                if (exchange == 1) {
                    critical_capacity = session
                        .critical_stream_send_scratch.payload.capacity;
                    critical_frames_capacity = session
                        .critical_stream_send_scratch.frames.capacity;
                    try std.testing.expect(critical_capacity != 0);
                    try std.testing.expect(critical_frames_capacity != 0);
                    critical_ptr = session.critical_stream_send_scratch.payload
                        .allocatedSlice().ptr;
                    critical_frames_ptr = session
                        .critical_stream_send_scratch.frames.allocatedSlice().ptr;
                } else if (exchange == 2) {
                    try std.testing.expectEqual(
                        critical_capacity,
                        session.critical_stream_send_scratch.payload.capacity,
                    );
                    try std.testing.expectEqual(
                        critical_frames_capacity,
                        session.critical_stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        critical_ptr,
                        session.critical_stream_send_scratch.payload
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        critical_frames_ptr,
                        session.critical_stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
                if (exchange != 0) {
                    try std.testing.expect(
                        session.qpack_encode.pending_sections.items.len != 0,
                    );
                }
            }
            try std.testing.expect(
                session.qpack_encoder_send.next_offset > 1,
            );
            try std.testing.expect(
                session.qpack_decoder_send.next_offset > 1,
            );
            try std.testing.expectEqual(
                @as(?usize, 512),
                session.qpack_encode.peer_max_capacity,
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
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 512 },
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 5,
            },
        },
    );
    defer client.deinit();

    var encoded_capacity: usize = 0;
    var encoded_ptr: [*]u8 = undefined;
    var critical_capacity: usize = 0;
    var critical_frames_capacity: usize = 0;
    var critical_ptr: [*]u8 = undefined;
    var critical_frames_ptr: [*]quic.Frame = undefined;
    for (0..3) |exchange| {
        var response = try client.request(.{
            .method = "GET",
            .path = "/handshake-dynamic",
            .authority = "example.test",
            .headers = &.{.{
                .name = "x-handshake-request",
                .value = "repeated-request-value",
            }},
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        var repeated_value: ?[]const u8 = null;
        for (response.response.headers) |header| {
            if (std.mem.eql(u8, header.name, "x-handshake-response")) {
                repeated_value = header.value;
            }
        }
        try std.testing.expectEqualStrings(
            "repeated-response-value",
            repeated_value orelse return error.TestUnexpectedResult,
        );
        // Complete HEADERS now submit borrowed fragments directly, retaining
        // only encoded field-section storage between these dynamic exchanges.
        try std.testing.expectEqual(@as(usize, 0), client.stream_send_scratch.frames.capacity);
        if (exchange == 0) {
            encoded_capacity = client.stream_send_scratch.encoded.capacity;
            try std.testing.expect(encoded_capacity != 0);
            encoded_ptr = client.stream_send_scratch.encoded
                .allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                encoded_capacity,
                client.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                encoded_ptr,
                client.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
        }
        if (exchange == 1) {
            critical_capacity =
                client.critical_stream_send_scratch.payload.capacity;
            critical_frames_capacity =
                client.critical_stream_send_scratch.frames.capacity;
            try std.testing.expect(critical_capacity != 0);
            try std.testing.expect(critical_frames_capacity != 0);
            critical_ptr = client.critical_stream_send_scratch.payload
                .allocatedSlice().ptr;
            critical_frames_ptr = client.critical_stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else if (exchange == 2) {
            try std.testing.expectEqual(
                critical_capacity,
                client.critical_stream_send_scratch.payload.capacity,
            );
            try std.testing.expectEqual(
                critical_frames_capacity,
                client.critical_stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                critical_ptr,
                client.critical_stream_send_scratch.payload
                    .allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                critical_frames_ptr,
                client.critical_stream_send_scratch.frames
                    .allocatedSlice().ptr,
            );
        }
    }

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(client.qpack_encode.known_received_count != 0);
    try std.testing.expect(client.qpack_decode.table.insert_count != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(client.qpack_encoder_send.next_offset > 1);
    try std.testing.expect(client.qpack_decoder_send.next_offset > 1);
    try std.testing.expectEqual(
        @as(?usize, 512),
        client.qpack_encode.peer_max_capacity,
    );
}

test "HTTP/3 handshake request failures keep stream cursors and QPACK transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x3d, 0x3e, 0x3f, 0x40 };
    const settings: http3.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
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
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .random = [_]u8{0x41} ** 32,
                .x25519_secret_key = [_]u8{0x42} ** 32,
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
            const expected_ids = [_]u62{ 0, 4 };
            for (expected_ids) |expected_id| {
                var request = try session.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqual(expected_id, request.stream_id);
                var header_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(
                        u8,
                        header.name,
                        "x-request-transaction",
                    )) {
                        header_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "reused-value",
                    header_value orelse return error.TestUnexpectedResult,
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 204,
                });
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
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .random = [_]u8{0x43} ** 32,
                .x25519_secret_key = [_]u8{0x44} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 256 },
            },
        },
    );
    defer client.deinit();

    _ = try client.receivePeerSettingsWithTimeout(.fromSeconds(2));
    try std.testing.expectError(error.InvalidHeader, client.sendRequest(.{
        .method = "GET",
        .path = "/invalid-before-reserve",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "invalid" }},
    }));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(!client.control.settings.sent);
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
    try std.testing.expect(client.qpack_encoder_prefix_sent);
    const qpack_offset = client.qpack_encoder_send.next_offset;
    _ = try client.qpack_encode.insertField(
        "x-request-transaction",
        "reused-value",
    );
    try std.testing.expect(
        client.qpack_encode.pendingEncoderInstructions().len != 0,
    );
    const inserted_before_request = client.qpack_encode.table.insert_count;

    const FailSendIo = struct {
        delegate: std.Io,
        fail_on_call: usize,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == self.fail_on_call) {
                return .{ error.NetworkDown, 0 };
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var failed = FailSendIo{
        .delegate = client.endpoint.io,
        .fail_on_call = 2,
    };
    var failed_vtable = failed.delegate.vtable.*;
    failed_vtable.netSend = FailSendIo.netSend;
    client.endpoint.io = .{ .userdata = &failed, .vtable = &failed_vtable };
    defer client.endpoint.io = failed.delegate;

    const request: http3.Request = .{
        .method = "GET",
        .path = "/request-transaction",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-request-transaction",
            .value = "reused-value",
        }},
    };
    try std.testing.expectError(error.NetworkDown, client.sendRequest(request));
    try std.testing.expectEqual(@as(usize, 2), failed.calls);
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 4),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expect(client.request_lifecycle.contains(0));
    try std.testing.expectEqual(@as(usize, 1), client.request_lifecycle.count());
    const aggregate_failed_stream = client.established.connection
        .sendStreamStats(0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 0),
        aggregate_failed_stream.highest_sent_offset,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        aggregate_failed_stream.final_size,
    );
    try std.testing.expect(
        client.qpack_encoder_send.next_offset > qpack_offset,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pendingEncoderInstructions().len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(
        client.qpack_encode.table.insert_count > inserted_before_request,
    );
    try std.testing.expect(!client.established.connection.closed());

    client.endpoint.io = failed.delegate;
    const aggregate_id = try client.trySendRequest(request);
    try std.testing.expectEqual(@as(u62, 0), aggregate_id);
    var aggregate_response = try client.receiveResponseWithTimeout(
        aggregate_id,
        .fromSeconds(2),
    );
    defer aggregate_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), aggregate_response.response.status);
    try std.testing.expectEqual(@as(usize, 0), client.qpack_encode.pendingEncoderInstructions().len);

    failed.calls = 0;
    failed.fail_on_call = 1;
    client.endpoint.io = .{ .userdata = &failed, .vtable = &failed_vtable };
    try std.testing.expectError(
        error.NetworkDown,
        client.startRequest(request, 0),
    );
    try std.testing.expectEqual(@as(usize, 1), failed.calls);
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 8),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expect(client.request_lifecycle.contains(4));
    try std.testing.expectEqual(@as(usize, 1), client.request_lifecycle.count());
    if (client.established.connection.sendStreamStats(4)) |failed_stream| {
        try std.testing.expectEqual(
            @as(u64, 0),
            failed_stream.highest_sent_offset,
        );
        try std.testing.expectEqual(
            @as(?u64, null),
            failed_stream.final_size,
        );
    }
    try std.testing.expect(client.outbound_bodies.find(4) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(!client.established.connection.closed());

    client.endpoint.io = failed.delegate;
    const streaming_id = try client.tryStartRequest(request, 0);
    try std.testing.expectEqual(@as(u62, 4), streaming_id);
    var streaming_response = try client.receiveResponseWithTimeout(
        streaming_id,
        .fromSeconds(2),
    );
    defer streaming_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), streaming_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;

    failed.calls = 0;
    client.endpoint.io = .{ .userdata = &failed, .vtable = &failed_vtable };
    try std.testing.expectError(
        error.NetworkDown,
        client.startRequest(request, 0),
    );
    try std.testing.expectEqual(@as(u62, 8), client.next_stream_id);
    try std.testing.expect(client.request_lifecycle.contains(8));
    failed.calls = 0;
    try std.testing.expectError(
        error.NetworkDown,
        client.cancelRequest(
            8,
            http3.ApplicationErrorCode.request_cancelled,
        ),
    );
    try std.testing.expect(client.established.connection.closed());
    try std.testing.expectEqual(@as(u62, 12), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
}

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
                session.established.early_data_status,
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

test "HTTP/3 handshake runtime decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const client_cid = [_]u8{ 0xf8, 0xf9, 0xfa, 0xfb };
    const server_cid = [_]u8{ 0xfc, 0xfd, 0xfe, 0xff };
    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
        .session = .{
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
            },
            .max_stream_frame_data = 1024,
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
            // Advertise capacity before accepting any dependent encoder
            // instruction or field section.
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
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/handshake-qpack", request.request.path);
            var value: ?[]const u8 = null;
            for (request.request.headers) |header| {
                if (std.mem.eql(u8, header.name, "x-handshake")) {
                    value = header.value;
                }
            }
            try std.testing.expectEqualStrings("dynamic", value orelse
                return error.TestUnexpectedResult);
            try std.testing.expectEqual(
                @as(u64, 1),
                session.qpack_decode.table.insert_count,
            );
            try std.testing.expectEqual(
                @as(u64, 1),
                session.options.local_settings.qpack_blocked_streams,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
        },
        .session = .{
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    });
    defer client.deinit();

    // Process the server SETTINGS and critical-stream prefixes before using
    // its advertised QPACK capacity.
    var settings_packet = try client.established.connection.receivePacket();
    defer settings_packet.deinit(allocator);
    for (settings_packet.frames) |frame| {
        if (frame != .stream) continue;
        if ((frame.stream.stream_id & 0x02) != 0 and
            frame.stream.stream_id == server_qpack_encoder_stream_id)
        {
            try client.qpack_decode.applyEncoderStreamFrame(
                &client.control,
                frame.stream,
            );
            continue;
        }
        _ = try applyControlStreamFrameForRole(
            &client.control,
            allocator,
            frame.stream,
            .client,
        );
    }
    try std.testing.expectEqual(
        @as(u64, 256),
        client.control.settings.peer.qpack_max_table_capacity,
    );

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
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-handshake", "dynamic");
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/handshake-qpack" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-handshake", .value = "dynamic" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&message, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        message.items,
        message.items.len,
        true,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    // Deliver the dependent message first, then unblock it with split encoder
    // instructions on the persistent stream.
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-handshake",
            .value = "dynamic",
        } },
    );
    frames.clearRetainingCapacity();
    try client.qpack_encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 runtime exchanges request and response over QUIC UDP frame endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3", request.request.path);
            try std.testing.expectEqualStrings("ping split by dev sender", request.request.body);
            try std.testing.expect(request.extra_datagrams.len != 0);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong split by dev sender",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3",
        .authority = "localhost",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping split by dev sender",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("pong split by dev sender", response.response.body);
}

test "HTTP/3 dev request deadline validates and resumes a partial STREAM" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
    );
    defer server.deinit();
    var client = try quic.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        },
    );
    defer client.deinit();

    // Validation happens before socket progress or request-state mutation.
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.zero),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const body = "retained after the bounded receive expires";
    try (http3.Request{
        .method = "POST",
        .path = "/dev-request-deadline",
        .authority = "localhost",
        .body = body,
    }).write(&encoded, allocator);
    const split = encoded.items.len - body.len + body.len / 2;
    try client.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items[0..split],
    } }});

    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        server.request_streams.count(),
    );

    try client.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = split,
        .data = encoded.items[split..],
        .fin = true,
    } }});
    var request = try server.receiveRequestWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer request.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), request.stream_id);
    try std.testing.expectEqualStrings(
        "/dev-request-deadline",
        request.request.path,
    );
    try std.testing.expectEqualStrings(body, request.request.body);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );
}

test "HTTP/3 dev runtime assembles split STREAM request and response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/split", request.request.path);
            try std.testing.expectEqualStrings("split request body", request.request.body);
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expect(request.extra_datagrams.len != 0);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "split response body",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            const first = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }};
            const second = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }};
            try server_ptr.quic_server.sendFrames(request.from, &first);
            try server_ptr.quic_server.sendFrames(request.from, &second);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var encoded_request: std.ArrayList(u8) = .empty;
    defer encoded_request.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/split",
        .authority = "localhost",
        .body = "split request body",
    }).write(&encoded_request, allocator);
    const split = encoded_request.items.len / 2;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = encoded_request.items[0..split],
        .fin = false,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = split,
        .data = encoded_request.items[split..],
        .fin = true,
    } }};
    try client.quic_client.sendFrames(&first);
    try client.quic_client.sendFrames(&second);

    var assembled = try receiveRuntimeStreamBytes(
        &client.quic_client.endpoint,
        server.address(),
        0,
        client.limits.max_stream_buffer,
    );
    defer assembled.deinit(allocator);
    try std.testing.expect(assembled.datagrams.len > 1);
    var response = try http3.decodeResponse(allocator, assembled.bytes);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("split response body", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client assembles split STREAM response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("/split-response", request.request.path);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .body = "client public API assembled this split response",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }});
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "GET",
        .path = "/split-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("client public API assembled this split response", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client deadline validation does not send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    const request_options: http3.Request = .{
        .method = "GET",
        .path = "/must-not-send",
        .authority = "localhost",
    };
    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(request_options, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndTimeout(
            request_options,
            null,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expect(!client.request_unusable);
    client.next_stream_id = std.math.maxInt(u62) - 3;
    try std.testing.expectError(
        error.StreamCreationError,
        client.request(request_options),
    );
    try std.testing.expectEqual(
        @as(u62, std.math.maxInt(u62) - 3),
        client.next_stream_id,
    );
    try std.testing.expect(!client.request_unusable);
    client.next_stream_id = 0;
    client.limits.max_stream_frame_data = 0;
    try std.testing.expectError(
        error.InvalidStreamRange,
        client.request(request_options),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expect(!client.request_unusable);

    // Neither deadline validation nor local frame preflight emitted stream
    // zero, and the latter did not poison the client.
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );
}

test "HTTP/3 development body deadline distinguishes retry from fail close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 96 } },
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .quic = .{ .max_datagram_size = 96 },
            .max_stream_frame_data = 32,
        },
    );
    defer client.deinit();
    const body = [_]u8{0xa5} ** 256;
    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/bounded-body",
        .authority = "localhost",
    }, body.len);
    const before = client.outbound_bodies.find(stream_id).?.*;
    var progress: DevelopmentBodyWriteProgress = .{
        .send_attempted = true,
        .completed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyWithDeadline(
            stream_id,
            &body,
            true,
            &progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    const after_invalid = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expect(!progress.send_attempted);
    try std.testing.expect(!progress.completed);
    try std.testing.expectEqual(before.written, after_invalid.written);
    try std.testing.expectEqual(
        before.send.next_offset,
        after_invalid.send.next_offset,
    );
    try std.testing.expect(!client.request_unusable);

    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };
    var timed = DeadlineAfterSendIo{
        .delegate = client.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.quic_client.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    defer client.quic_client.endpoint.io = timed.delegate;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyWithDeadline(
            stream_id,
            &body,
            true,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expect(progress.send_attempted);
    try std.testing.expect(!progress.completed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
    try std.testing.expect(client.request_unusable);
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.sendRequestBody(stream_id, "must-not-replay", false),
    );
}

test "HTTP/3 dev client bounded requests deliver informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var request = try self.server.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    self.server.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/bounded-timeout",
                    request.request.path,
                );
                try self.server.sendResponse(
                    request.from,
                    request.stream_id,
                    .{ .status = 204 },
                );
            }
            {
                var request = try self.server.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    self.server.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/bounded-informational",
                    request.request.path,
                );
                try self.server.sendResponseWithInformational(
                    request.from,
                    request.stream_id,
                    &.{.{
                        .status = 103,
                        .headers = &.{.{
                            .name = "link",
                            .value = "</dev.css>",
                        }},
                    }},
                    .{
                        .status = 200,
                        .headers = &.{.{
                            .name = "date",
                            .value = "Sun, 06 Nov 1994 08:49:37 GMT",
                        }},
                        .body = "bounded final",
                    },
                );
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();
    var unrelated = try quic.runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer unrelated.deinit();
    var spoofed: std.ArrayList(u8) = .empty;
    defer spoofed.deinit(allocator);
    try (http3.Response{
        .status = 500,
        .body = "wrong peer",
    }).write(&spoofed, allocator);
    try unrelated.sendFrames(client.address(), &.{.{ .stream = .{
        .stream_id = 0,
        .data = spoofed.items,
        .fin = true,
    } }});
    // Consume the queued spoof deterministically before the real server can
    // reply. The bounded request path must discard it and continue waiting.
    std.Io.sleep(io, .fromMilliseconds(5), .awake) catch {};
    var no_content = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/bounded-timeout",
        .authority = "localhost",
    }, .fromSeconds(1));
    defer no_content.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), no_content.response.status);
    const automatic_date = server_response.headerValue(
        no_content.response.headers,
        "date",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(usize, server_response.date_value_len),
        automatic_date.len,
    );

    const Observation = struct {
        client: *Client,
        count: usize = 0,
        status: u16 = 0,
        header_valid: bool = false,
        saw_date: bool = false,
        error_seen: ?anyerror = null,
        stream_error_seen: ?anyerror = null,
        unexpectedly_read: bool = false,

        fn observe(
            context: *anyopaque,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
            self.status = response.status;
            for (response.headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "date")) {
                    self.saw_date = true;
                }
                if (std.mem.eql(u8, header.name, "link") and
                    std.mem.eql(u8, header.value, "</dev.css>"))
                {
                    self.header_valid = true;
                }
            }
            var datagram = self.client.receiveDatagramWithTimeout(
                .fromMilliseconds(1),
            ) catch |err| {
                self.error_seen = err;
                self.probeDevelopmentStream();
                return;
            };
            defer datagram.deinit(self.client.quic_client.endpoint.allocator);
            self.unexpectedly_read = true;
            self.probeDevelopmentStream();
        }

        fn probeDevelopmentStream(self: *@This()) void {
            var stream = self.client.pollDevelopmentStream(.{
                .session_id = 0,
                .local_role = .client,
            }) catch |err| {
                self.stream_error_seen = err;
                return;
            } orelse return;
            defer stream.deinit();
            self.unexpectedly_read = true;
        }
    };
    var observation = Observation{ .client = &client };
    var response = try client.requestWithInformationalAndDeadline(
        .{
            .method = "GET",
            .path = "/bounded-informational",
            .authority = "localhost",
        },
        .{
            .context = &observation,
            .on_response = Observation.observe,
        },
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observation.count);
    try std.testing.expect(!observation.unexpectedly_read);
    switch (observation.error_seen orelse
        return error.TestUnexpectedResult) {
        error.ConcurrentRead => {},
        else => return error.TestUnexpectedResult,
    }
    switch (observation.stream_error_seen orelse
        return error.TestUnexpectedResult) {
        error.ConcurrentRead => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u16, 103), observation.status);
    try std.testing.expect(observation.header_valid);
    try std.testing.expect(!observation.saw_date);
    try std.testing.expectEqualStrings(
        "bounded final",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        server_response.headerValue(response.response.headers, "date") orelse
            return error.TestUnexpectedResult,
    );
    var date_count: usize = 0;
    for (response.response.headers) |header| {
        date_count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, "date"));
    }
    try std.testing.expectEqual(@as(usize, 1), date_count);
    try std.testing.expect(!client.request_unusable);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client fails closed after partial response timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "response deliberately left incomplete",
    }).write(&encoded, allocator);
    const split = encoded.items.len / 2;
    // Queue an incomplete stream-zero response before the request. This keeps
    // the test deterministic while exercising the client's actual socket and
    // call-local STREAM assembly.
    try server.quic_server.sendFrames(client.address(), &.{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items[0..split],
    } }});

    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(.{
            .method = "GET",
            .path = "/partial-response",
            .authority = "localhost",
        }, .fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_unusable);
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);

    // The first request did reach the server; a retry is rejected locally and
    // cannot allocate or emit stream four.
    var request = try server.receiveRequestWithTimeout(.fromSeconds(1));
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/partial-response",
        request.request.path,
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = "GET",
            .path = "/must-fail-closed",
            .authority = "localhost",
        }),
    );
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
}

test "HTTP/3 development server aggregate response fails closed after send attempt" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .quic = .{ .max_datagram_size = 4096 },
            .max_stream_frame_data = 4,
        },
    );
    defer server.deinit();

    const PartialSend = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == 2) return .{ error.NetworkDown, 0 };
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    var partial = PartialSend{ .delegate = server.quic_server.endpoint.io };
    var vtable = partial.delegate.vtable.*;
    vtable.netSend = PartialSend.netSend;
    server.quic_server.endpoint.io = .{
        .userdata = &partial,
        .vtable = &vtable,
    };
    defer server.quic_server.endpoint.io = partial.delegate;

    const valid_frame_size = server.limits.max_stream_frame_data;
    server.limits.max_stream_frame_data = 0;
    try std.testing.expectError(
        error.InvalidStreamRange,
        server.sendResponse(receiver.address(), 0, .{
            .status = 200,
            .body = "preflight failure",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), partial.calls);
    try std.testing.expect(
        !server.aggregate_response_unusable.load(.acquire),
    );
    server.limits.max_stream_frame_data = valid_frame_size;

    try std.testing.expectError(
        error.NetworkDown,
        server.sendResponse(receiver.address(), 0, .{
            .status = 200,
            .body = "response split across several datagrams",
        }),
    );
    try std.testing.expect(partial.calls >= 2);
    try std.testing.expect(
        server.aggregate_response_unusable.load(.acquire),
    );

    const calls = partial.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        server.sendResponse(receiver.address(), 4, .{ .status = 204 }),
    );
    try std.testing.expectEqual(calls, partial.calls);
}

test "HTTP/3 dev runtime enforces stream reassembly limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer receiver.deinit();
    var sender = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, receiver.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer sender.deinit();

    try sender.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 32,
        .data = "too-far",
        .fin = true,
    } }});
    try std.testing.expectError(
        error.StreamBufferTooLarge,
        receiveRuntimeStreamBytes(&receiver, sender.address(), 0, 16),
    );
}

test "HTTP/3 dev runtime receives requests with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        batch: ?OwnedRequestBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.server.receiveRequestsConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_b.deinit();

    const req_a = http3.Request{ .method = "POST", .path = "/batch-a", .authority = "localhost", .body = "a" };
    const req_b = http3.Request{ .method = "POST", .path = "/batch-b", .authority = "localhost", .body = "b" };
    var encoded_a: std.ArrayList(u8) = .empty;
    defer encoded_a.deinit(allocator);
    var encoded_b: std.ArrayList(u8) = .empty;
    defer encoded_b.deinit(allocator);
    try req_a.write(&encoded_a, allocator);
    try req_b.write(&encoded_b, allocator);
    const frame_a = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_a.items, .fin = true } }};
    const frame_b = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_b.items, .fin = true } }};
    try client_a.quic_client.sendFrames(&frame_a);
    try client_b.quic_client.sendFrames(&frame_b);

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_a = false;
    var saw_b = false;
    for (batch.requests) |maybe_request| {
        const request = maybe_request.?;
        if (std.mem.eql(u8, request.request.path, "/batch-a")) saw_a = true;
        if (std.mem.eql(u8, request.request.path, "/batch-b")) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test {
    _ = @import("development/tests/message.zig");
    _ = @import("development/tests/send.zig");
    _ = @import("datagram/tests/routing.zig");
    _ = handshake_client_pool;
    _ = connect_datagram;
    _ = @import("qpack/state_tests.zig");
    _ = @import("qpack/tests/writer.zig");
    _ = @import("qpack/tests/integration.zig");
    _ = @import("qpack/tests/request_transport.zig");
    _ = @import("qpack/tests/response_transport.zig");
    _ = @import("control/receive_tests.zig");
    _ = @import("control/tests/integration.zig");
    _ = @import("control/send_tests.zig");
    _ = @import("receive/routing/tests/request.zig");
    _ = @import("receive/routing/tests/response.zig");
    _ = @import("receive/tests/connection_error.zig");
    _ = @import("receive/tests/runtime_close.zig");
    _ = @import("send/tests/body.zig");
    _ = @import("send/tests/paced_body.zig");
    _ = @import("send/tests/message.zig");
    _ = @import("send/tests/partial_send.zig");
    _ = @import("stream/reader_tests.zig");
    _ = @import("stream/set_tests.zig");
    _ = @import("stream/push/state_tests.zig");
    _ = @import("stream/push/tests/control.zig");
    _ = @import("stream/push/tests/events.zig");
    _ = @import("stream/push/tests/aggregate.zig");
    _ = @import("stream/push/tests/aggregate_state.zig");
    _ = @import("stream/push/tests/send.zig");
    _ = @import("server/tests/protected.zig");
    _ = @import("server/tests/gro.zig");
    _ = @import("server/tests/limits.zig");
    _ = @import("server/tests/lifecycle.zig");
    _ = @import("server/tests/streaming.zig");
    _ = @import("server/tests/receive.zig");
    _ = @import("server/complete_response_tests.zig");
    _ = @import("client/tests/protected.zig");
    _ = @import("client/tests/deadline.zig");
    _ = @import("client/resolver_tests.zig");
    _ = @import("client/happy_eyeballs_tests.zig");
    _ = @import("client/owned_head_tests.zig");
    _ = @import("client/complete_request.zig");
    _ = @import("qpack/tests/cancellation.zig");
    _ = @import("qpack/tests/decoder_progress.zig");
    _ = @import("connect_udp_tests.zig");
    _ = @import("connect_udp_dispatcher_relay_tests.zig");
    _ = @import("connect_ip_tests.zig");
    _ = @import("connect_ip_dispatcher_tests.zig");
    _ = @import("client/batch_tests.zig");
    _ = @import("redirect_tests.zig");
    _ = @import("client/tests/streaming.zig");
    _ = @import("handshake_client_pool_tests.zig");
    _ = @import("handshake_client_pool/admission_tests.zig");
    _ = @import("handshake_client_pool/retirement_tests.zig");
    _ = @import("handshake_client_pool/return_tests.zig");
    _ = @import("handshake_client_pool/batch_tests.zig");
    _ = @import("handshake_client_pool/shared_tests.zig");
    _ = @import("handshake_client_pool/shared_route_tests.zig");
    _ = @import("handshake_client_pool/shared_authority_tests.zig");
    _ = @import("handshake_client_pool_redirect_tests.zig");
    _ = @import("shared_handshake_client_pool_tests.zig");
    _ = @import("shared_handshake_client_pool_socks5_tests.zig");
    _ = @import("shared_handshake_client_pool_happy_eyeballs_tests.zig");
    _ = @import("shared_handshake_client_pool_request_tests.zig");
    _ = @import("shared_handshake_client_pool_stream_tests.zig");
    _ = @import("shared_handshake_client_pool_stream_dispatcher_tests.zig");
    _ = @import("shared_handshake_client_pool_dispatcher_tests.zig");
    _ = @import("shared_handshake_client_pool_handshake_progress_tests.zig");
    _ = @import("shared_handshake_client_pool_concurrent_handshake_tests.zig");
    _ = @import("shared_handshake_client_pool/alt_svc_tests.zig");
    _ = @import("shared_handshake_client_pool_redirect_tests.zig");
    _ = @import("development_streaming_tests.zig");
    _ = @import("development_server_tests.zig");
    _ = @import("development/server_peer/state_tests.zig");
    _ = @import("endpoint_dispatcher_tests.zig");
    _ = @import("endpoint_server_tests.zig");
    _ = @import("endpoint_handler_supervisor_tests.zig");
    _ = @import("handshake_server_serve_tests.zig");
    _ = @import("cancellation_tests.zig");
    _ = @import("early_data_tests.zig");
    _ = @import("informational_tests.zig");
    _ = @import("recovery_tests.zig");
    _ = @import("response_scheduler/tests/integration.zig");
    _ = @import("response_scheduler/tests/protected.zig");
}

test "HTTP/3 Expect parsing accepts case-insensitive comma lists" {
    const list = [_]http3.Qpack.HeaderField{
        .{ .name = "expect", .value = "custom, 100-Continue" },
    };
    try std.testing.expect(runtime.requestHeadersExpectContinue(&list));

    const repeated = [_]http3.Qpack.HeaderField{
        .{ .name = "x-other", .value = "100-continue" },
        .{ .name = "Expect", .value = "custom" },
        .{ .name = "expect", .value = "100-continue, other" },
    };
    try std.testing.expect(runtime.requestHeadersExpectContinue(&repeated));

    const absent = [_]http3.Qpack.HeaderField{
        .{ .name = "expect", .value = "custom" },
    };
    try std.testing.expect(!runtime.requestHeadersExpectContinue(&absent));

    const near = [_]http3.Qpack.HeaderField{
        .{ .name = "expect", .value = "100-continuex" },
    };
    try std.testing.expect(!runtime.requestHeadersExpectContinue(&near));
}

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
    _ = @import("body_streaming_tests.zig");
    _ = @import("concurrent_tests.zig");
    _ = @import("connect_datagram_tests.zig");
    _ = @import("development_runtime_tests.zig");
    _ = @import("early_request_tests.zig");
    _ = @import("handshake_deadline_tests.zig");
    _ = @import("push_and_response_deadline_tests.zig");
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

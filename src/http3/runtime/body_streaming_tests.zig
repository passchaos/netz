//! HTTP/3 body streaming, GRO batch, and small-window tests.

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
        // The server thread is already blocked in receiveRequest. Close the
        // connection so it can observe a terminal state and exit before the
        // join; otherwise the skip path itself deadlocks.
        client.established.connection.closeApplication(0, "") catch {};
        thread.join();
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

            const timed_delegate_io = session.established.connection.endpoint.io;
            var timed: NativeSendIo = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .now_ns = .init(@intCast(std.Io.Clock.awake.now(
                session.established.connection.endpoint.io,
            ).nanoseconds)), .advance_after_send_ns = std.time.ns_per_s };
            defer timed.backend.deinit();
            session.established.connection.endpoint.io = timed.io();
            defer session.established.connection.endpoint.io = timed_delegate_io;

            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "jk", "lmno", "pqr" },
                    true,
                    &progress,
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(timed.now_ns.load(.acquire) + 1),
                    },
                ),
            );
            try std.testing.expectEqual(@as(usize, 3), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);
            try std.testing.expectEqual(@as(usize, 1), timed.send_calls.load(.acquire));

            session.established.connection.endpoint.io = timed_delegate_io;
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

    const timed_delegate_io = client.endpoint.io;
    var timed: NativeSendIo = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .now_ns = .init(@intCast(std.Io.Clock.awake.now(client.endpoint.io).nanoseconds)), .advance_after_send_ns = std.time.ns_per_s };
    defer timed.backend.deinit();
    client.endpoint.io = timed.io();
    defer client.endpoint.io = timed_delegate_io;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns.load(.acquire) + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls.load(.acquire));

    client.endpoint.io = timed_delegate_io;
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

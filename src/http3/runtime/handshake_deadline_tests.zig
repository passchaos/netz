//! HTTP/3 handshake and request deadline tests.

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

test "HTTP/3 aggregate deadlines bound request and response head sends" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const DeadlineSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
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
            .initial_one_rtt_config = .{
                .max_datagram_size = 1400,
                .pacing_max_burst_packets = 1,
            },
            .random = [_]u8{0x51} ** 32,
            .x25519_secret_key = [_]u8{0x52} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        body_done: std.Io.Event = .unset,
        response_timeout: bool = false,
        body_timeout: bool = false,
        zero_send_calls: bool = false,
        zero_sleep_calls: bool = false,
        lifecycle_retained: bool = false,
        connection_open: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.body_done.set(self.io);
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
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expectEqualStrings("/after-timeout", request.request.path);

            const before_invalid_deadline =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponsePacedWithDeadline(
                    request.stream_id,
                    .{ .status = 204 },
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                before_invalid_deadline,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
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
            var fixed = DeadlineSendIo{
                .delegate = session.established.connection.endpoint.io,
            };
            var vtable = fixed.delegate.vtable.*;
            vtable.now = DeadlineSendIo.now;
            vtable.sleep = DeadlineSendIo.sleep;
            vtable.netSend = DeadlineSendIo.netSend;
            session.established.connection.endpoint.io = .{
                .userdata = &fixed,
                .vtable = &vtable,
            };
            quic.one_rtt.testing.exhaustPacingAt(
                &session.established.connection,
                @intCast(fixed.now_ns),
            );
            const packet_number =
                session.established.connection.next_packet_number;
            if (session.sendResponsePacedWithDeadline(
                request.stream_id,
                .{ .status = 204 },
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(fixed.now_ns + 1),
                },
            )) |_| {
                return error.TestUnexpectedResult;
            } else |err| {
                if (err != error.Timeout) return err;
                self.response_timeout = true;
            }
            self.zero_send_calls = fixed.send_calls == 0;
            self.zero_sleep_calls = fixed.sleep_calls == 0;
            self.lifecycle_retained =
                session.request_lifecycle.count() == 1;
            self.connection_open =
                !session.established.connection.closed();
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            session.established.connection.endpoint.io = fixed.delegate;
            try session.sendResponsePacedWithDeadline(
                request.stream_id,
                .{ .status = 204 },
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );

            var body_request = try session.receiveRequest();
            defer body_request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), body_request.stream_id);
            try std.testing.expectEqualStrings(
                "/body-timeout",
                body_request.request.path,
            );
            const now = std.Io.Clock.awake.now(
                session.established.connection.endpoint.io,
            ).nanoseconds;
            fixed = .{
                .delegate = session.established.connection.endpoint.io,
                .now_ns = now,
            };
            vtable = fixed.delegate.vtable.*;
            vtable.now = DeadlineSendIo.now;
            vtable.sleep = DeadlineSendIo.sleep;
            vtable.netSend = DeadlineSendIo.netSend;
            session.established.connection.endpoint.io = .{
                .userdata = &fixed,
                .vtable = &vtable,
            };
            quic.one_rtt.testing.exhaustPacingAt(
                &session.established.connection,
                @intCast(fixed.now_ns),
            );
            fixed.now_ns += std.time.ns_per_s;
            var body: [4096]u8 = .{0xa5} ** 4096;
            if (session.sendResponsePacedWithDeadline(
                body_request.stream_id,
                .{ .status = 200, .body = &body },
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(fixed.now_ns + 1),
                },
            )) |_| {
                return error.TestUnexpectedResult;
            } else |err| {
                if (err != error.Timeout) return err;
                self.body_timeout = true;
            }
            try std.testing.expect(fixed.send_calls >= 1);
            try std.testing.expect(!session.established.connection.closed());
            try std.testing.expect(!session.request_lifecycle.contains(body_request.stream_id));
            session.established.connection.endpoint.io = fixed.delegate;
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
            .initial_one_rtt_config = .{
                .max_datagram_size = 1400,
                .pacing_max_burst_packets = 1,
            },
            .random = [_]u8{0x53} ** 32,
            .x25519_secret_key = [_]u8{0x54} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(
            .{
                .method = "GET",
                .path = "/wrong-clock",
                .authority = "localhost",
            },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

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
    var fixed = DeadlineSendIo{ .delegate = client.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = DeadlineSendIo.now;
    vtable.sleep = DeadlineSendIo.sleep;
    vtable.netSend = DeadlineSendIo.netSend;
    client.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed.now_ns),
    );
    const packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndDeadline(
            .{
                .method = "GET",
                .path = "/must-not-send",
                .authority = "localhost",
            },
            null,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed.send_calls);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    try std.testing.expectEqual(packet_number, client.established.connection.next_packet_number);
    try std.testing.expectEqual(@as(usize, 1), client.request_lifecycle.count());
    try std.testing.expect(client.request_lifecycle.contains(0));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expect(!client.established.connection.closed());
    client.endpoint.io = fixed.delegate;

    var response = try client.requestWithDeadline(
        .{
            .method = "GET",
            .path = "/after-timeout",
            .authority = "localhost",
        },
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    _ = try client.sendRequest(.{
        .method = "GET",
        .path = "/body-timeout",
        .authority = "localhost",
    });
    try shared.body_done.wait(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.response_timeout);
    try std.testing.expect(shared.body_timeout);
    try std.testing.expect(shared.zero_send_calls);
    try std.testing.expect(shared.zero_sleep_calls);
    try std.testing.expect(shared.lifecycle_retained);
    try std.testing.expect(shared.connection_open);
}

test "HTTP/3 streaming head deadlines validate before state mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c };
    const client_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    const server_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
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
            .random = [_]u8{0x65} ** 32,
            .x25519_secret_key = [_]u8{0x66} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        checked: bool = false,
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
            const packet_number =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                session.startResponseWithDeadline(
                    request.stream_id,
                    .{ .status = 200 },
                    4,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
            );
            try session.startResponseWithDeadline(
                request.stream_id,
                .{ .status = 204 },
                0,
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );
            self.checked = true;
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
            .random = [_]u8{0x67} ** 32,
            .x25519_secret_key = [_]u8{0x68} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.startRequestWithDeadline(
            .{
                .method = "POST",
                .path = "/wrong-clock",
                .authority = "localhost",
            },
            4,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

    const request_id = try client.startRequestWithDeadline(.{
        .method = "GET",
        .path = "/server-check",
        .authority = "localhost",
    }, 0, .fromNow(
        client.connectionIo(),
        .{ .raw = .fromSeconds(2), .clock = .awake },
    ));
    try std.testing.expectEqual(@as(u62, 0), request_id);
    var response = try client.receiveResponse(request_id);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.checked);
}

test "HTTP/3 request deadline bounds bidirectional stream admission" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_streams_bidi = 0;
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
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            std.Io.sleep(
                session.connectionIo(),
                .fromMilliseconds(100),
                .awake,
            ) catch |err| {
                self.err = err;
            };
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
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(
            .{
                .method = "GET",
                .path = "/stream-credit-timeout",
                .authority = "localhost",
            },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(!client.established.connection.closed());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

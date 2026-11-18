//! HTTP/3 push, priority, interleaved-response, and client-deadline tests.

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

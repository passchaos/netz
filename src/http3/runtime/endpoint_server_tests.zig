const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const ObservedBatchSend =
    @import("../../quic/one_rtt/tests/observed_batch_send.zig")
        .ObservedBatchSend;

const net = std.Io.net;

const EndpointFixedClockIo = struct {
    delegate: std.Io,
    now_ns: i96,
    sleep_calls: usize = 0,

    fn now(
        userdata: ?*anyopaque,
        _: std.Io.Clock,
    ) std.Io.Timestamp {
        const self: *EndpointFixedClockIo = @ptrCast(@alignCast(userdata));
        return .fromNanoseconds(self.now_ns);
    }

    fn sleep(
        userdata: ?*anyopaque,
        _: std.Io.Timeout,
    ) std.Io.Cancelable!void {
        const self: *EndpointFixedClockIo = @ptrCast(@alignCast(userdata));
        self.sleep_calls += 1;
        return error.Canceled;
    }
};

test "HTTP/3 endpoint request polling defers paced feedback" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );
    const settings = http3.Settings{
        .qpack_max_table_capacity = 512,
        .qpack_blocked_streams = 2,
    };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 32;
    server_transport.initial_max_stream_data_bidi_remote = 32;
    var session = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{
            .local_settings = settings,
            .max_stream_frame_data = 1200,
        },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "poll-feedback-server",
            .peer_connection_id = "poll-feedback-client",
            .local_transport_parameters = server_transport,
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
                .receive_window = 32,
                .stream_receive_window = 32,
            },
        },
    );
    defer session.deinit();
    session.control.settings.markSent(settings);
    session.control.settings.markReceived(settings);
    session.qpack_encoder_prefix_sent = true;
    session.qpack_decoder_prefix_sent = true;

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/paced-poll",
        .authority = "localhost",
    }).write(&request_bytes, allocator);
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "poll-feedback-client",
        .peer_connection_id = "poll-feedback-server",
        .enable_pacing = false,
    });
    defer peer.deinit();
    try peer.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = request_bytes.items,
    } }});
    var request_packet = try session.established.connection.receivePacket();
    errdefer request_packet.deinit(allocator);
    try session.processRequestPacketView(.{
        .from = request_packet.from,
        .packet_number = request_packet.packet.packet_number,
        .frames = request_packet.frames,
        .peer_initiated_key_update = request_packet.peer_initiated_key_update,
    });
    request_packet.deinit(allocator);
    var head = (try session.pollRequestEvent()) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expect(head.message.value == .head);

    for (0..1400) |_| {
        try session.qpack_decode.recordStreamCancellation(0);
    }
    const feedback_len =
        session.qpack_decode.pendingDecoderInstructions().len;
    try std.testing.expect(feedback_len != 0);
    const decoder_offset = session.qpack_decoder_send.next_offset;
    const request_available = quic.one_rtt.testing
        .receiveStreamAvailableLen(&session.established.connection, 0).?;
    try std.testing.expect(request_available != 0);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 79;
    try dispatcher.registerConnection(
        handle,
        &session.established.connection,
    );
    var promoted = runtime.PromotedHandshakeSession{
        .dispatcher = &dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = &session,
    };

    var fixed_io = EndpointFixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = EndpointFixedClockIo.now;
    fixed_vtable.sleep = EndpointFixedClockIo.sleep;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &session.established.connection,
        @intCast(fixed_io.now_ns),
    );

    const packet_number = session.established.connection.next_packet_number;
    try std.testing.expect(
        (try runtime.EndpointServer.testing.pollSessionRequestEntry(
            &promoted,
        )) == null,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        session.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(
        feedback_len,
        session.qpack_decode.pendingDecoderInstructions().len,
    );
    try std.testing.expectEqual(
        decoder_offset,
        session.qpack_decoder_send.next_offset,
    );
    try std.testing.expectEqual(
        request_available,
        quic.one_rtt.testing.receiveStreamAvailableLen(
            &session.established.connection,
            0,
        ).?,
    );

    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(
        (try runtime.EndpointServer.testing.pollSessionRequestEntry(
            &promoted,
        )) == null,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(
        session.qpack_decode.pendingDecoderInstructions().len != 0,
    );
    try std.testing.expect(
        session.qpack_decode.pendingDecoderInstructions().len < feedback_len,
    );
    try std.testing.expect(
        session.qpack_decoder_send.next_offset > decoder_offset,
    );
    try std.testing.expectEqual(
        request_available,
        quic.one_rtt.testing.receiveStreamAvailableLen(
            &session.established.connection,
            0,
        ).?,
    );

    while (session.qpack_decode.pendingDecoderInstructions().len != 0) {
        const feedback_timer = dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            quic.one_rtt.TimerDeadlineKind.pacing,
            feedback_timer.timer.kind,
        );
        fixed_io.now_ns = @intCast(feedback_timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(
            feedback_timer.timer.deadline_ns,
        )) orelse return error.TestUnexpectedResult;
        try std.testing.expect(
            (try runtime.EndpointServer.testing.pollSessionRequestEntry(
                &promoted,
            )) == null,
        );
        try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
        try std.testing.expectEqual(
            request_available,
            quic.one_rtt.testing.receiveStreamAvailableLen(
                &session.established.connection,
                0,
            ).?,
        );
    }
    try std.testing.expect(
        session.qpack_decoder_send.next_offset > decoder_offset,
    );

    const credit_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        credit_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(credit_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        credit_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(
        (try runtime.EndpointServer.testing.pollSessionRequestEntry(
            &promoted,
        )) == null,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(
            &session.established.connection,
            0,
        ).?,
    );
}

test "HTTP/3 endpoint malformed request cancellation is retryable" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf3} ** quic.protection.secret_len,
    );
    var session = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{},
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "malformed-server",
            .peer_connection_id = "malformed-client",
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer session.deinit();
    session.control.settings.markSent(.{});
    session.control.settings.markReceived(.{});
    session.qpack_encoder_prefix_sent = true;
    session.qpack_decoder_prefix_sent = true;

    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeLiteralBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/invalid" },
        .{ .name = ":scheme", .value = "https" },
    });
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "malformed-client",
        .peer_connection_id = "malformed-server",
        .enable_pacing = false,
    });
    defer peer.deinit();
    try peer.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = request_bytes.items,
    } }});
    var packet = try session.established.connection.receivePacket();
    defer packet.deinit(allocator);
    try session.processRequestPacket(&packet);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 80;
    try dispatcher.registerConnection(
        handle,
        &session.established.connection,
    );
    var promoted = runtime.PromotedHandshakeSession{
        .dispatcher = &dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = &session,
    };

    var fixed_io = EndpointFixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = EndpointFixedClockIo.now;
    fixed_vtable.sleep = EndpointFixedClockIo.sleep;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &session.established.connection,
        @intCast(fixed_io.now_ns),
    );

    const packet_number = session.established.connection.next_packet_number;
    try std.testing.expectError(
        error.InvalidHeader,
        runtime.EndpointServer.testing.pollSessionRequestEntry(&promoted),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        session.established.connection.next_packet_number,
    );
    try std.testing.expect(session.streaming_requests.find(0) != null);
    try std.testing.expect(
        session.established.connection.sendStreamStats(0).?.reset == null,
    );
    try std.testing.expect(
        session.established.connection.recvStreamStats(0).?
            .stop_sending_sent == null,
    );

    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectError(
        error.InvalidHeader,
        runtime.EndpointServer.testing.pollSessionRequestEntry(&promoted),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(session.streaming_requests.find(0) == null);
    try std.testing.expect(
        session.established.connection.sendStreamStats(0).?.reset != null,
    );
    try std.testing.expect(
        session.established.connection.recvStreamStats(0).?
            .stop_sending_sent != null,
    );
}

test "HTTP/3 endpoint server exposes bounded callback loop API" {
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "receiveOnce"));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveManyOnce",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveTransportWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "receiveTransportWithTimeout",
    ));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "serveUntil"));
    try std.testing.expect(@hasDecl(
        runtime.EndpointServer,
        "serveHandlersUntil",
    ));
    try std.testing.expect(@hasDecl(runtime, "EndpointServeEvent"));
    try std.testing.expect(@hasDecl(runtime, "EndpointServeOptions"));
    try std.testing.expect(@hasDecl(runtime, "EndpointHandlerServeOptions"));
}

test "HTTP/3 endpoint batch receive retains requests beyond caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .handshake = .{ .local_connection_id = "batch-root" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );
    const client_cid = "batch-client";
    const server_cid = "batch-server";
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = client_cid,
        .peer_connection_id = server_cid,
        .enable_pacing = false,
    });
    defer peer.deinit();
    const session = try allocator.create(runtime.HandshakeServerSession);
    var session_owned = true;
    defer if (session_owned) {
        session.deinit();
        allocator.destroy(session);
    };
    session.* = try runtime.HandshakeServerSession.initPreconfigured(
        &server.quic_server.endpoint,
        peer_endpoint.address(),
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    session.control.settings.markSent(.{});
    session.control.settings.markReceived(.{});
    session.qpack_encoder_prefix_sent = true;
    session.qpack_decoder_prefix_sent = true;
    try session.bindDispatcher();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 91;
    try endpoint.dispatcher.registerConnection(
        handle,
        &session.established.connection,
    );
    const slot = try endpoint.sessions.getOrPut(allocator, handle);
    try std.testing.expect(!slot.found_existing);
    slot.value_ptr.* = .{
        .dispatcher = endpoint.dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = session,
    };
    session_owned = false;

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var storage: [2 * 4096]u8 = undefined;
    var events: [2]runtime.EndpointServerEvent = undefined;
    var no_events: [0]runtime.EndpointServerEvent = .{};
    try std.testing.expectError(
        error.BufferTooShort,
        endpoint.receiveManyOnce(
            &versions,
            &storage,
            &no_events,
            .{ .clock = .awake, .raw = .fromSeconds(1) },
        ),
    );
    try std.testing.expectError(
        error.InvalidHandshakeRecovery,
        endpoint.receiveManyOnce(
            &versions,
            &storage,
            &events,
            .{ .clock = .awake, .raw = .zero },
        ),
    );
    var too_many_events: [
        quic.runtime.max_receive_batch_messages + 1
    ]runtime.EndpointServerEvent = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        endpoint.receiveManyOnce(
            &versions,
            &storage,
            &too_many_events,
            .{ .clock = .awake, .raw = .fromSeconds(1) },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try endpoint.receiveManyOnce(
            &versions,
            &storage,
            &events,
            .{ .clock = .awake, .raw = .fromMilliseconds(1) },
        ),
    );

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/batch-one",
        .authority = "localhost",
    }).write(&first, allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/batch-two",
        .authority = "localhost",
    }).write(&second, allocator);
    try peer.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = first.items,
        .fin = true,
    } }});
    try peer.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = second.items,
        .fin = true,
    } }});

    const count = try endpoint.receiveManyOnce(
        &versions,
        &storage,
        &events,
        .{ .clock = .awake, .raw = .fromSeconds(1) },
    );
    defer for (events[0..count]) |*event| event.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), count);
    @memset(&storage, 0xaa);

    var saw_first = false;
    var saw_second = false;
    for (events[0..count]) |event| switch (event) {
        .request => |request| {
            try std.testing.expectEqual(handle, request.connection_handle);
            switch (request.request) {
                .reset => return error.TestUnexpectedResult,
                .message => |message| switch (message.value) {
                    .push_promise, .data_available, .trailers, .finished => return error.TestUnexpectedResult,
                    .head => |head_value| switch (head_value) {
                        .response => return error.TestUnexpectedResult,
                        .request => |head| {
                            try std.testing.expectEqualStrings("GET", head.method);
                            if (std.mem.eql(u8, head.path, "/batch-one")) {
                                saw_first = true;
                            } else if (std.mem.eql(u8, head.path, "/batch-two")) {
                                saw_second = true;
                            } else {
                                return error.TestUnexpectedResult;
                            }
                        },
                    },
                },
            }
        },
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(saw_first and saw_second);
}

test "HTTP/3 handshake server rejects a non-positive recovery drain budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidHandshakeRecovery,
        runtime.HandshakeServer.bind(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            .{},
            .{
                .handshake = .{ .local_connection_id = "invalid-drain" },
                .serve_connection_recovery_drain_timeout = .zero,
            },
        ),
    );
}

test "HTTP/3 endpoint callback refreshes timers after application sends" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "timer-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const session_ptr = try allocator.create(runtime.HandshakeServerSession);
    errdefer allocator.destroy(session_ptr);
    session_ptr.* = try runtime.HandshakeServerSession.initPreconfigured(
        &server.quic_server.endpoint,
        .{ .ip4 = .loopback(9102) },
        .{},
        .{
            .receive_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xd1} ** quic.protection.secret_len,
            ),
            .send_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xd2} ** quic.protection.secret_len,
            ),
            .local_connection_id = "timer-active",
            .peer_connection_id = "timer-peer",
        },
    );
    var session_owned = true;
    defer if (session_owned) {
        session_ptr.deinit();
        allocator.destroy(session_ptr);
    };
    const connection_handle: quic.endpoint_dispatcher.ConnectionHandle = 78;
    try endpoint.dispatcher.registerConnection(
        connection_handle,
        &session_ptr.established.connection,
    );
    const slot = try endpoint.sessions.getOrPut(allocator, connection_handle);
    try std.testing.expect(!slot.found_existing);
    slot.value_ptr.* = .{
        .dispatcher = endpoint.dispatcher,
        .allocator = allocator,
        .handle = connection_handle,
        .session = session_ptr,
    };
    session_owned = false;

    // Registration sees no pending recovery and therefore has no timer. The
    // callback creates reliable work without an intervening inbound packet.
    try std.testing.expect(endpoint.dispatcher.nextTimerDeadline() == null);
    const Context = struct {
        fn handle(
            _: *@This(),
            _: *runtime.EndpointServer,
            event: runtime.EndpointServeEvent,
        ) !void {
            try std.testing.expect(event == .request);
            try event.request.session.established.connection.send(&.{.{
                .ping = {},
            }});
        }
    };
    var context: Context = .{};
    var request_event = runtime.EndpointServerEvent{ .request = .{
        .connection_handle = connection_handle,
        .request = .{ .reset = .{
            .from = .{ .ip4 = .loopback(9102) },
            .stream_id = 0,
            .application_error_code = 0,
        } },
    } };
    defer request_event.deinit(allocator);
    // Exercise the same callback-and-refresh boundary as serveUntil without a
    // network handshake or timing race.
    try runtime.EndpointServer.testing.dispatchServeEvent(
        &endpoint,
        Context,
        &context,
        &request_event,
        Context.handle,
    );
    const timer = endpoint.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(connection_handle, timer.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pto,
        timer.timer.kind,
    );

    const TakeContext = struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        taken: ?runtime.PromotedHandshakeSession = null,

        fn run(
            self: *@This(),
            server_value: *runtime.EndpointServer,
            _: *runtime.EndpointTransportEvent,
        ) !void {
            self.taken = server_value.takeSession(self.handle) orelse
                return error.TestUnexpectedResult;
        }
    };
    var take_context = TakeContext{ .handle = connection_handle };
    var take_event = runtime.EndpointTransportEvent{
        .connected = connection_handle,
    };
    defer take_event.deinit(allocator);
    // A protocol adapter may transfer the session during its callback. The
    // common post-callback refresh must not touch the removed owner.
    try runtime.EndpointServer.testing.dispatchTransportServeEvent(
        &endpoint,
        TakeContext,
        &take_context,
        &take_event,
        TakeContext.run,
    );
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
    var taken = take_context.taken orelse return error.TestUnexpectedResult;
    take_context.taken = null;
    taken.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        endpoint.dispatcher.connectionCount(),
    );
}

test "HTTP/3 endpoint transport callback refreshes timers after adapter sends" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "transport-timer-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const session_ptr = try allocator.create(runtime.HandshakeServerSession);
    errdefer allocator.destroy(session_ptr);
    session_ptr.* = try runtime.HandshakeServerSession.initPreconfigured(
        &server.quic_server.endpoint,
        .{ .ip4 = .loopback(9103) },
        .{},
        .{
            .receive_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xe1} ** quic.protection.secret_len,
            ),
            .send_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xe2} ** quic.protection.secret_len,
            ),
            .local_connection_id = "timer-active",
            .peer_connection_id = "timer-peer",
        },
    );
    var session_owned = true;
    defer if (session_owned) {
        session_ptr.deinit();
        allocator.destroy(session_ptr);
    };
    const connection_handle: quic.endpoint_dispatcher.ConnectionHandle = 79;
    try endpoint.dispatcher.registerConnection(
        connection_handle,
        &session_ptr.established.connection,
    );
    const slot = try endpoint.sessions.getOrPut(allocator, connection_handle);
    try std.testing.expect(!slot.found_existing);
    slot.value_ptr.* = .{
        .dispatcher = endpoint.dispatcher,
        .allocator = allocator,
        .handle = connection_handle,
        .session = session_ptr,
    };
    session_owned = false;
    try std.testing.expect(endpoint.dispatcher.nextTimerDeadline() == null);

    const Context = struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,

        fn run(
            self: *@This(),
            server_value: *runtime.EndpointServer,
            event: *runtime.EndpointTransportEvent,
        ) !void {
            try std.testing.expect(event.* == .connected);
            const session = server_value.session(self.handle) orelse
                return error.TestUnexpectedResult;
            try session.established.connection.send(&.{.{ .ping = {} }});
        }
    };
    var context = Context{ .handle = connection_handle };
    var event = runtime.EndpointTransportEvent{
        .connected = connection_handle,
    };
    defer event.deinit(allocator);
    try runtime.EndpointServer.testing.dispatchTransportServeEvent(
        &endpoint,
        Context,
        &context,
        &event,
        Context.run,
    );
    const timer = endpoint.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(connection_handle, timer.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pto,
        timer.timer.kind,
    );
}

test "HTTP/3 endpoint request poll mirrors automatic stream-credit retry timer" {
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
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );
    const client_cid = "poll-timer-client";
    const server_cid = "poll-timer-server";
    var client = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = client_cid,
            .peer_connection_id = server_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer client.deinit();
    var session = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client.address(),
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer session.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 80;
    try dispatcher.registerConnection(handle, &session.established.connection);
    var promoted = runtime.PromotedHandshakeSession{
        .dispatcher = &dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = &session,
        .registered = false,
    };

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/poll-timer",
        .authority = "localhost",
    });
    var head = try session.receiveRequestEvent();
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expect(head.message.value == .head);
    try std.testing.expectEqual(stream_id, head.message.stream_id);
    try session.sendResponse(stream_id, .{ .status = 204 });

    // The test is interested in the automatic MAX_STREAMS emitted by polling
    // the terminal request event, not the already-submitted response. Retire
    // all response recovery records as if the peer ACK arrived, then reset the
    // endpoint's mirror to the resulting timer state.
    for (0..64) |packet_number| {
        _ = session.established.connection.markPacketAcknowledged(
            packet_number,
        );
    }
    try std.testing.expectEqual(
        @as(usize, 0),
        session.established.connection.pendingRecoveryCount(),
    );
    try dispatcher.refreshConnectionTimer(handle);
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);

    var failed_send = ObservedBatchSend{
        .delegate = server_endpoint.io,
        .fail_after_prefix = 0,
    };
    server_endpoint.io = failed_send.io();
    defer server_endpoint.io = failed_send.delegate;

    var finished = (try runtime.EndpointServer.testing
        .pollSessionRequestEntry(&promoted)) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .message);
    try std.testing.expect(finished.message.value == .finished);
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(
        !session.established.connection.peerStreamClosed(stream_id),
    );

    const connection_timer = session.established.connection
        .nextTimerDeadline() orelse return error.TestUnexpectedResult;
    const endpoint_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, endpoint_timer.connection_id);
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.peer_stream_credit,
        endpoint_timer.timer.kind,
    );

    server_endpoint.io = failed_send.delegate;
    _ = (try dispatcher.serviceNextTimerAt(
        endpoint_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(
        session.established.connection.peerStreamClosed(stream_id),
    );
}

test "HTTP/3 endpoint request poll refreshes timers before returning an error" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    var session = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        .{ .ip4 = .loopback(9104) },
        .{},
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "poll-error-server",
            .peer_connection_id = "poll-error-client",
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer session.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 81;
    try dispatcher.registerConnection(handle, &session.established.connection);
    var promoted = runtime.PromotedHandshakeSession{
        .dispatcher = &dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = &session,
        .registered = false,
    };

    // Simulate application work performed since the last dispatcher event.
    // The subsequent protocol poll fails before returning an event, but the
    // endpoint must still mirror this reliable packet's PTO.
    try session.established.connection.send(&.{.{ .ping = {} }});
    const connection_timer = session.established.connection
        .nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pto,
        connection_timer.kind,
    );
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);

    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    session.qpack_decode.allocator = failed_alloc.allocator();
    defer session.qpack_decode.allocator = allocator;
    try std.testing.expectError(
        error.OutOfMemory,
        runtime.EndpointServer.testing.pollSessionRequestEntry(&promoted),
    );
    try std.testing.expect(failed_alloc.has_induced_failure);

    const endpoint_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, endpoint_timer.connection_id);
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
}

test "HTTP/3 endpoint packet error replaces stale timer with close expiry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .handshake = .{ .local_connection_id = "packet-error-root" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe9} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xea} ** quic.protection.secret_len,
    );
    const client_cid = "packet-error-client";
    const server_cid = "packet-error-server";
    var client = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = client_cid,
            .peer_connection_id = server_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer client.deinit();
    const session = try allocator.create(runtime.HandshakeServerSession);
    var session_owned = true;
    defer if (session_owned) {
        session.deinit();
        allocator.destroy(session);
    };
    session.* = try runtime.HandshakeServerSession.initPreconfigured(
        &server.quic_server.endpoint,
        client.address(),
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 82;
    try endpoint.dispatcher.registerConnection(
        handle,
        &session.established.connection,
    );
    const slot = try endpoint.sessions.getOrPut(allocator, handle);
    try std.testing.expect(!slot.found_existing);
    slot.value_ptr.* = .{
        .dispatcher = endpoint.dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = session,
    };
    session_owned = false;
    try session.established.connection.send(&.{.{ .ping = {} }});
    try endpoint.dispatcher.refreshConnectionTimer(handle);
    const before = endpoint.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, before.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pto,
        before.timer.kind,
    );

    // A FIN on the peer's control stream is H3_CLOSED_CRITICAL_STREAM. QUIC
    // accepts and routes the packet first; HTTP/3 then emits CONNECTION_CLOSE
    // and returns the protocol error from the endpoint iteration. Its default
    // three-PTO close expiry must replace the stale pre-parser PTO.
    try client.established.connection.send(&.{.{ .stream = .{
        .stream_id = 2,
        .data = &.{@intFromEnum(http3.StreamType.control)},
        .fin = true,
    } }});
    try std.testing.expectError(
        error.ClosedCriticalStream,
        endpoint.receiveOnce(
            &.{quic.Version.version_1.wireValue()},
            .{ .clock = .awake, .raw = .fromSeconds(1) },
        ),
    );
    try std.testing.expect(session.established.connection.closing());
    const connection_timer = session.established.connection
        .nextTimerDeadline() orelse return error.TestUnexpectedResult;
    const endpoint_timer = endpoint.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, endpoint_timer.connection_id);
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.close,
        endpoint_timer.timer.kind,
    );
    try std.testing.expect(
        endpoint_timer.timer.deadline_ns != before.timer.deadline_ns,
    );
    const serviced = (try endpoint.dispatcher.serviceNextTimerAt(
        endpoint_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.close,
        serviced.timer.kind,
    );
    try std.testing.expect(session.established.connection.closed());
}

test "HTTP/3 endpoint server validates receive deadlines" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "deadline-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();
    const versions = &.{quic.Version.version_1.wireValue()};

    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveTransportWithDeadline(
            versions,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveTransportWithTimeout(versions, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveWithTimeout(versions, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveWithDeadline(versions, .fromNow(io, .{
            .clock = .awake,
            .raw = .zero,
        })),
    );
    try std.testing.expectError(
        error.Timeout,
        endpoint.receiveWithDeadline(versions, .fromNow(io, .{
            .clock = .awake,
            .raw = .fromMilliseconds(5),
        })),
    );
}

test "HTTP/3 endpoint reports an admission timeout as a typed failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "timeout-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const bytes = try allocator.dupe(u8, "expired-initial");
    var initial = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(9010) },
            .bytes = bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = bytes[0..8],
        .source_connection_id = bytes[8..],
        .first_packet_len = bytes.len,
    } };
    defer initial.deinit(allocator);
    const admission = try allocator.create(runtime.HandshakeAdmission);
    admission.* = try server.beginHandshakeAdmission(
        endpoint.dispatcher,
        73,
        &initial,
        .{ .max_pending_handshakes = 1, .inbox_capacity = 1 },
    );
    // Model the worker result after the deadline expires. The completion owns
    // the admission and must unregister/free it while preserving Timeout in
    // the endpoint event rather than returning it as a receive-loop failure.
    var completion = runtime.HandshakeCompletion{
        .handle = 73,
        .admission = admission,
        .result = .{ .failure = error.Timeout },
    };
    var event = try runtime.EndpointServer.testing.finishTransportCompletion(
        &endpoint,
        &completion,
    );
    defer event.deinit(allocator);
    try std.testing.expect(event == .handshake_failed);
    try std.testing.expectEqual(@as(usize, 73), event.handshake_failed.handle);
    try std.testing.expectEqual(error.Timeout, event.handshake_failed.err);
    try std.testing.expectEqual(
        @as(usize, 0),
        endpoint.dispatcher.pendingHandshakeCount(),
    );
}

test "HTTP/3 endpoint server rotates ready request sessions fairly" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "h3-fair-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    // Only the map keys and stable value addresses are observed by the test
    // callback. Remove them before teardown so undefined protocol state is
    // never passed to PromotedHandshakeSession.deinit.
    var dummy_session: runtime.HandshakeServerSession = undefined;
    var promoted_storage: [3]runtime.PromotedHandshakeSession = undefined;
    defer endpoint.sessions.clearRetainingCapacity();
    const handles = [_]quic.endpoint_dispatcher.ConnectionHandle{ 41, 52, 63 };
    for (handles, 0..) |handle, index| {
        promoted_storage[index] = .{
            .dispatcher = endpoint.dispatcher,
            .allocator = allocator,
            .handle = handle,
            .session = &dummy_session,
            .registered = false,
        };
        try endpoint.sessions.put(
            allocator,
            handle,
            promoted_storage[index],
        );
    }

    var order: [handles.len]quic.endpoint_dispatcher.ConnectionHandle =
        undefined;
    for (&order) |*handle| {
        handle.* = (try runtime.EndpointServer.testing.pollReadyRequestHandle(
            &endpoint,
            &handles,
        )) orelse return error.TestUnexpectedResult;
    }
    for (order, 0..) |handle, index| {
        for (order[0..index]) |earlier| {
            try std.testing.expect(handle != earlier);
        }
    }
    try std.testing.expectEqual(
        order[0],
        (try runtime.EndpointServer.testing.pollReadyRequestHandle(
            &endpoint,
            &handles,
        )).?,
    );

    const only_middle = [_]quic.endpoint_dispatcher.ConnectionHandle{
        order[1],
    };
    try std.testing.expectEqual(
        order[1],
        (try runtime.EndpointServer.testing.pollReadyRequestHandle(
            &endpoint,
            &only_middle,
        )).?,
    );
    try std.testing.expectEqual(
        order[2],
        (try runtime.EndpointServer.testing.pollReadyRequestHandle(
            &endpoint,
            &handles,
        )).?,
    );

    const stale = order[2];
    try std.testing.expect(endpoint.sessions.remove(stale));
    endpoint.last_request_handle = stale;
    const after_removal =
        (try runtime.EndpointServer.testing.pollReadyRequestHandle(
            &endpoint,
            &handles,
        )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(after_removal != stale);
}

test "HTTP/3 endpoint server owns concurrent handshakes and requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = "server-template",
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();
    var endpoint_server = try runtime.EndpointServer.init(
        &server,
        .{ .max_pending_handshakes = 2, .inbox_capacity = 8 },
    );
    var endpoint_server_owned = true;
    defer if (endpoint_server_owned) endpoint_server.deinit();

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        random: [32]u8,
        secret: [32]u8,
        client: ?runtime.HandshakeClient = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            self.client = try runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{ .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 16,
                } },
                .{ .handshake = .{
                    .original_destination_connection_id = self.original_dcid,
                    .local_connection_id = self.local_cid,
                    .server_name = "localhost",
                    .random = self.random,
                    .x25519_secret_key = self.secret,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                } },
            );
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "endpoint-one",
            .local_cid = "client-one",
            .random = [_]u8{0xd3} ** 32,
            .secret = [_]u8{0xd4} ** 32,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "endpoint-two",
            .local_cid = "client-two",
            .random = [_]u8{0xd5} ** 32,
            .secret = [_]u8{0xd6} ** 32,
        },
    };
    const thread_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const thread_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        if (endpoint_server_owned) {
            endpoint_server.deinit();
            endpoint_server_owned = false;
        }
        thread_a.join();
        thread_b.join();
        for (&clients) |*client| {
            if (client.client) |*value| value.deinit();
        }
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var connected: usize = 0;
    var receive_storage: [2 * 4096]u8 = undefined;
    var events: [2]runtime.EndpointServerEvent = undefined;
    while (connected < clients.len) {
        const count = try endpoint_server.receiveManyOnce(
            &versions,
            &receive_storage,
            &events,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
        );
        for (events[0..count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .connected => |handle| {
                    const promoted = endpoint_server.session(handle) orelse
                        return error.TestUnexpectedResult;
                    try std.testing.expect(promoted.control.settings.sent);
                    try std.testing.expect(promoted.qpack_encoder_prefix_sent);
                    try std.testing.expect(promoted.qpack_decoder_prefix_sent);
                    connected += 1;
                },
                .closed => return error.TestUnexpectedResult,
                .handshake_failed => |failure| return failure.err,
                .request, .unrouted => return error.TestUnexpectedResult,
            }
        }
    }

    thread_a.join();
    thread_b.join();
    joined = true;
    for (&clients) |*client| {
        if (client.err) |err| return err;
        var value = client.client orelse return error.TestUnexpectedResult;
        defer value.deinit();
        try std.testing.expectEqualStrings("h3", value.negotiatedAlpn());
        client.client = null;
    }
    try std.testing.expectEqual(@as(usize, 2), endpoint_server.connectionCount());
}

test "HTTP/3 endpoint total connection limit releases on removal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "capacity-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .max_connections = 1,
        .inbox_capacity = 2,
    });
    defer endpoint.deinit();

    var connection = try quic.one_rtt.Connection.init(
        &server.quic_server.endpoint,
        .{
            .peer = .{ .ip4 = .loopback(9001) },
            .receive_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xc1} ** quic.protection.secret_len,
            ),
            .send_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xc2} ** quic.protection.secret_len,
            ),
            .local_connection_id = "capacity-active",
            .peer_connection_id = "capacity-peer",
        },
    );
    defer connection.deinit();
    try endpoint.dispatcher.registerConnection(99, &connection);

    const bytes = try allocator.dupe(u8, "capacity-initial");
    var initial = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(9002) },
            .bytes = bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = bytes[0..8],
        .source_connection_id = bytes[8..],
        .first_packet_len = bytes.len,
    } };
    defer initial.deinit(allocator);
    try std.testing.expectError(
        error.PendingHandshakeLimitReached,
        endpoint.handshakes.admit(&initial),
    );
    try std.testing.expect(initial == .new_initial);
    try std.testing.expect(try endpoint.dispatcher.unregisterConnection(99));
    // The same Initial can enter the bounded inbox after a live slot is freed.
    _ = try endpoint.handshakes.admit(&initial);
    try std.testing.expect(initial == .consumed);
}

test "HTTP/3 endpoint transport loop observes shutdown while idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "endpoint-idle" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const Context = struct {
        calls: usize = 0,
        fn handle(
            self: *@This(),
            _: *runtime.EndpointServer,
            _: *runtime.EndpointTransportEvent,
        ) !void {
            self.calls += 1;
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        shutdown: *std.Io.Event,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.endpoint.serveTransportUntil(
                Context,
                &self.context,
                Context.handle,
                &.{quic.Version.version_1.wireValue()},
                .{ .clock = .awake, .raw = .fromMilliseconds(2) },
                self.shutdown,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared{ .endpoint = &endpoint, .shutdown = &shutdown };
    const started = std.Io.Clock.awake.now(io);
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    shutdown.set(io);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            std.time.ns_per_s,
    );
}

test "HTTP/3 endpoint request loop observes shutdown while idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "endpoint-serve-idle" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const Context = struct {
        calls: usize = 0,

        fn handle(
            self: *@This(),
            _: *runtime.EndpointServer,
            _: runtime.EndpointServeEvent,
        ) !void {
            self.calls += 1;
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        shutdown: *std.Io.Event,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.endpoint.serveUntil(
                Context,
                &self.context,
                Context.handle,
                .{
                    .shutdown = self.shutdown,
                    .supported_versions = &.{
                        quic.Version.version_1.wireValue(),
                        quic.Version.version_2.wireValue(),
                    },
                    .poll_interval = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(2),
                    },
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared{ .endpoint = &endpoint, .shutdown = &shutdown };
    const started = std.Io.Clock.awake.now(io);
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    shutdown.set(io);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            std.time.ns_per_s,
    );
}

test "HTTP/3 endpoint callback loop serves concurrent connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = "endpoint-callback",
            .random = [_]u8{0xb1} ** 32,
            .x25519_secret_key = [_]u8{0xb2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        path: []const u8,
        expected_body: []const u8,
        random: [32]u8,
        secret: [32]u8,
        wait_before_request: bool = false,
        second_request: *std.Io.Event,
        completed: *std.atomic.Value(usize),
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.second_request.set(self.io);
                self.shutdown.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{ .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 16,
                } },
                .{ .handshake = .{
                    .original_destination_connection_id = self.original_dcid,
                    .local_connection_id = self.local_cid,
                    .server_name = "localhost",
                    .random = self.random,
                    .x25519_secret_key = self.secret,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                } },
            );
            defer client.deinit();
            if (self.wait_before_request) {
                try self.second_request.wait(self.io);
            }
            var response = try client.requestWithTimeout(
                .{
                    .method = "GET",
                    .path = self.path,
                    .authority = "localhost",
                },
                .fromSeconds(5),
            );
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(
                self.expected_body,
                response.response.body,
            );
            if (std.mem.eql(u8, self.path, "/one")) {
                var found = false;
                for (response.response.trailers) |trailer| {
                    if (std.ascii.eqlIgnoreCase(
                        trailer.name,
                        "x-finished",
                    )) {
                        try std.testing.expectEqualStrings(
                            "true",
                            trailer.value,
                        );
                        found = true;
                    }
                }
                try std.testing.expect(found);
            }
            if (self.completed.fetchAdd(1, .acq_rel) + 1 == 2) {
                self.shutdown.set(self.io);
            }
        }
    };
    var completed: std.atomic.Value(usize) = .init(0);
    var second_request: std.Io.Event = .unset;
    var shutdown: std.Io.Event = .unset;
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "endpoint-callback-1",
            .local_cid = "callback-client-one",
            .path = "/one",
            .expected_body = "response-one",
            .random = [_]u8{0xb3} ** 32,
            .secret = [_]u8{0xb4} ** 32,
            .second_request = &second_request,
            .completed = &completed,
            .shutdown = &shutdown,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "endpoint-callback-2",
            .local_cid = "callback-client-two",
            .path = "/two",
            .expected_body = "response-two",
            .random = [_]u8{0xb5} ** 32,
            .secret = [_]u8{0xb6} ** 32,
            .wait_before_request = true,
            .second_request = &second_request,
            .completed = &completed,
            .shutdown = &shutdown,
        },
    };
    const thread_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const thread_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        second_request.set(io);
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        thread_a.join();
        thread_b.join();
    };

    const Context = struct {
        heads: usize = 0,
        second_request: *std.Io.Event,
        first_session: ?*runtime.HandshakeServerSession = null,
        first_stream_id: ?u62 = null,

        fn handle(
            self: *@This(),
            _: *runtime.EndpointServer,
            event: runtime.EndpointServeEvent,
        ) !void {
            switch (event) {
                .connected => {},
                .closed => return error.TestUnexpectedResult,
                .request => |value| switch (value.request.*) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head_value| switch (head_value) {
                            .response => return error.TestUnexpectedResult,
                            .request => |head| {
                                try std.testing.expectEqualStrings(
                                    "GET",
                                    head.method,
                                );
                                try std.testing.expectError(
                                    error.InvalidDispatcherState,
                                    value.session.sendResponsePaced(
                                        message.stream_id,
                                        .{
                                            .status = 204,
                                            .request_method = head.method,
                                        },
                                    ),
                                );
                                const is_first = std.mem.eql(
                                    u8,
                                    head.path,
                                    "/one",
                                );
                                if (!is_first and !std.mem.eql(
                                    u8,
                                    head.path,
                                    "/two",
                                )) {
                                    return error.TestUnexpectedResult;
                                }
                                try std.testing.expect(
                                    value.session.dispatcherBound(),
                                );
                                if (is_first) {
                                    const now = std.Io.Clock.awake.now(
                                        value.session.established.connection
                                            .endpoint.io,
                                    ).nanoseconds;
                                    // Pin the empty pacer bucket beyond any
                                    // scheduler delay between this hook and
                                    // the one-attempt send. Using `now` made
                                    // the expected backpressure race with
                                    // byte-granular budget replenishment.
                                    quic.one_rtt.testing.exhaustPacingAt(
                                        &value.session.established.connection,
                                        @intCast(now + std.time.ns_per_s),
                                    );
                                    try std.testing.expectError(
                                        error.PacingLimited,
                                        value.session.tryStartResponse(
                                            message.stream_id,
                                            .{
                                                .status = 200,
                                                .request_method = head.method,
                                            },
                                            "response-one".len,
                                            true,
                                        ),
                                    );
                                    self.first_session = value.session;
                                    self.first_stream_id = message.stream_id;
                                    self.second_request.set(
                                        value.session.established.connection
                                            .endpoint.io,
                                    );
                                } else {
                                    // B is served while A remains backpressured.
                                    try value.session.trySendResponseLiteral(
                                        message.stream_id,
                                        .{
                                            .status = 200,
                                            .body = "response-two",
                                            .request_method = head.method,
                                        },
                                    );
                                    const first = self.first_session orelse
                                        return error.TestUnexpectedResult;
                                    const now = std.Io.Clock.awake.now(
                                        first.established.connection.endpoint.io,
                                    ).nanoseconds;
                                    quic.one_rtt.testing.setPacingBudgetAt(
                                        &first.established.connection,
                                        first.established.connection
                                            .currentSendDatagramSize(),
                                        @intCast(now),
                                    );
                                    try first.tryStartResponse(
                                        self.first_stream_id orelse
                                            return error.TestUnexpectedResult,
                                        .{
                                            .status = 200,
                                            .request_method = "GET",
                                        },
                                        "response-one".len,
                                        true,
                                    );
                                    try first.trySendResponseBody(
                                        self.first_stream_id.?,
                                        "response-one",
                                        false,
                                    );
                                    try first.tryFinishResponseTrailers(
                                        self.first_stream_id.?,
                                        &.{.{
                                            .name = "x-finished",
                                            .value = "true",
                                        }},
                                    );
                                    self.first_session = null;
                                    self.first_stream_id = null;
                                }
                                self.heads += 1;
                            },
                        },
                        .finished => {},
                        .data_available, .trailers, .push_promise => return error.TestUnexpectedResult,
                    },
                },
            }
        }
    };
    var context = Context{ .second_request = &second_request };
    try endpoint.serveUntil(
        Context,
        &context,
        Context.handle,
        .{
            .shutdown = &shutdown,
            .supported_versions = &.{
                quic.Version.version_1.wireValue(),
                quic.Version.version_2.wireValue(),
            },
            .poll_interval = .{
                .clock = .awake,
                .raw = .fromMilliseconds(2),
            },
        },
    );

    thread_a.join();
    thread_b.join();
    joined = true;
    for (&clients) |*client| if (client.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), context.heads);
    try std.testing.expect(context.first_session == null);
    try std.testing.expectEqual(@as(usize, 2), completed.load(.acquire));
}

test "HTTP/3 endpoint removes a connection when its close timer expires" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "close-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const session_ptr = try allocator.create(runtime.HandshakeServerSession);
    var session_owned = true;
    defer if (session_owned) {
        session_ptr.deinit();
        allocator.destroy(session_ptr);
    };
    session_ptr.* = try runtime.HandshakeServerSession.initPreconfigured(
        &server.quic_server.endpoint,
        .{ .ip4 = .loopback(9101) },
        .{},
        .{
            .receive_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xc1} ** quic.protection.secret_len,
            ),
            .send_keys = quic.protection.deriveAes128Keys(
                [_]u8{0xc2} ** quic.protection.secret_len,
            ),
            .local_connection_id = "close-active",
            .peer_connection_id = "close-peer",
        },
    );
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 77;
    try endpoint.dispatcher.registerConnection(
        handle,
        &session_ptr.established.connection,
    );
    const slot = try endpoint.sessions.getOrPut(allocator, handle);
    try std.testing.expect(!slot.found_existing);
    slot.value_ptr.* = .{
        .dispatcher = endpoint.dispatcher,
        .allocator = allocator,
        .handle = handle,
        .session = session_ptr,
    };
    session_owned = false;

    try session_ptr.established.connection.closeApplicationAt(
        0,
        "done",
        1,
        1,
    );
    try endpoint.dispatcher.refreshConnectionTimer(handle);
    const scheduled = endpoint.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    var event = (try endpoint.receiveTransportOnce(
        &.{quic.Version.version_1.wireValue()},
        .{ .clock = .awake, .raw = .fromMilliseconds(1) },
    )) orelse return error.TestUnexpectedResult;
    defer event.deinit(allocator);
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(handle, event.closed.handle);
    try std.testing.expectEqual(
        scheduled.timer.kind,
        event.closed.timer.kind,
    );
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint.dispatcher.routeCount());
}

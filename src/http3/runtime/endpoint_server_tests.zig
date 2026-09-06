const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const ObservedBatchSend =
    @import("../../quic/one_rtt/tests/observed_batch_send.zig")
        .ObservedBatchSend;

const net = std.Io.net;

test "HTTP/3 endpoint server exposes bounded callback loop API" {
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "receiveOnce"));
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
    try std.testing.expect(@hasDecl(runtime, "EndpointServeEvent"));
    try std.testing.expect(@hasDecl(runtime, "EndpointServeOptions"));
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
    var failed_vtable = server_endpoint.io.vtable.*;
    failed_vtable.netSend = ObservedBatchSend.netSend;
    server_endpoint.io = .{
        .userdata = &failed_send,
        .vtable = &failed_vtable,
    };
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
    while (connected < clients.len) {
        var event = try endpoint_server.receive(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => connected += 1,
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .request, .unrouted => return error.TestUnexpectedResult,
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
        completed: *std.atomic.Value(usize),
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
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
            var response = try client.request(.{
                .method = "GET",
                .path = self.path,
                .authority = "localhost",
            });
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(
                self.expected_body,
                response.response.body,
            );
            if (self.completed.fetchAdd(1, .acq_rel) + 1 == 2) {
                self.shutdown.set(self.io);
            }
        }
    };
    var completed: std.atomic.Value(usize) = .init(0);
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
            .completed = &completed,
            .shutdown = &shutdown,
        },
    };
    const thread_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const thread_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        thread_a.join();
        thread_b.join();
    };

    const Context = struct {
        heads: usize = 0,

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
                                const body = if (std.mem.eql(
                                    u8,
                                    head.path,
                                    "/one",
                                ))
                                    "response-one"
                                else if (std.mem.eql(u8, head.path, "/two"))
                                    "response-two"
                                else
                                    return error.TestUnexpectedResult;
                                try value.session.sendResponsePaced(
                                    message.stream_id,
                                    .{
                                        .status = 200,
                                        .body = body,
                                        .request_method = head.method,
                                    },
                                );
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
    var context: Context = .{};
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

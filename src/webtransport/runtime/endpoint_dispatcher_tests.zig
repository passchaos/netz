const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const handshake_stream = @import("stream.zig");
const session_control = @import("session_control.zig");
const ObservedBatchSend =
    @import("../../quic/one_rtt/tests/observed_batch_send.zig")
        .ObservedBatchSend;

// Establish the request before injecting a mock response. Modern CONNECT
// cannot be sent until the server SETTINGS have been processed.
fn startPendingMockRequest(server: *quic.one_rtt.Connection, pending: *runtime.PendingHandshakeConnect, settings_bytes: []const u8) !void {
    const connection = pending.connection();
    const pacing_enabled = connection.config.enable_pacing;
    connection.config.enable_pacing = false;
    defer connection.config.enable_pacing = pacing_enabled;
    try server.send(&.{.{ .stream = .{ .stream_id = 3, .data = settings_bytes } }});
    var packet = try connection.receivePacketServicingTimersDeadline(.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer packet.deinit(std.testing.allocator);
    try pending.processPacket(&packet);
    for (0..8) |_| {
        if (pending.queued_connect == null) return;
        try std.testing.expect((try pending.pollConnect()) == null);
    }
    return error.TestUnexpectedResult;
}

const FixedClockIo = struct {
    delegate: std.Io,
    now_ns: i96,
    send_calls: usize = 0,
    sleep_calls: usize = 0,

    fn now(
        userdata: ?*anyopaque,
        _: std.Io.Clock,
    ) std.Io.Timestamp {
        const self: *FixedClockIo = @ptrCast(@alignCast(userdata));
        return .fromNanoseconds(self.now_ns);
    }

    fn sleep(
        userdata: ?*anyopaque,
        _: std.Io.Timeout,
    ) std.Io.Cancelable!void {
        const self: *FixedClockIo = @ptrCast(@alignCast(userdata));
        self.sleep_calls += 1;
        return error.Canceled;
    }

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *FixedClockIo = @ptrCast(@alignCast(userdata));
        self.send_calls += 1;
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

test "WebTransport endpoint admission HEADERS do not wait for pacing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = "wt-admission-owner",
        } },
    );
    defer server.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf1} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{
        .qpack_max_table_capacity = 512,
        .qpack_blocked_streams = 2,
    });
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server.h3.quic_server.endpoint,
        peer_endpoint.address(),
        .{
            .local_settings = settings,
            .auto_date_header = false,
        },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-admission-server",
            .peer_connection_id = "wt-admission-client",
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    h3.qpack_encoder_prefix_sent = true;
    h3.qpack_decoder_prefix_sent = true;
    try h3.qpack_encode.configurePeerLimits(512, 2);
    _ = try h3.qpack_encode.insertField(
        "x-admission",
        "literal",
    );
    h3.qpack_encode.clearEncoderInstructions();

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Request{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/paced-admission",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport" },
            http3.capsule.protocol_header,
        },
    }).write(&request_bytes, allocator);
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-admission-client",
        .peer_connection_id = "wt-admission-server",
        .enable_pacing = false,
    });
    defer peer.deinit();
    try peer.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = request_bytes.items,
    } }});
    var request_packet = try h3.established.connection.receivePacket();
    defer request_packet.deinit(allocator);
    try h3.processRequestPacket(&request_packet);
    var request_event = (try h3.pollRequestEventOnce()) orelse
        return error.TestUnexpectedResult;
    defer request_event.deinit(allocator);
    var request_head = switch (request_event) {
        .message => |*message| switch (message.value) {
            .head => |head| switch (head) {
                .request => |request| blk: {
                    const value = request;
                    message.value = .finished;
                    break :blk value;
                },
                .response => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        .reset => return error.TestUnexpectedResult,
    };
    var request_head_owned = true;
    defer if (request_head_owned) request_head.deinit(allocator);

    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 16;
    try endpoint.h3.dispatcher.registerConnection(
        handle,
        &h3.established.connection,
    );
    const pending = try allocator.create(runtime.EndpointPendingSession);
    pending.* = .{
        .handle = handle,
        .h3 = &h3,
        .request = .{ .stream_id = 0, .request = request_head },
        .session_id = .init(0),
        .limits = endpoint.limits,
    };
    request_head_owned = false;
    try endpoint.pending.put(allocator, handle, pending);

    var fixed_io = FixedClockIo{
        .delegate = server.h3.quic_server.endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server.h3.quic_server.endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    server.h3.quic_server.endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server.h3.quic_server.endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &h3.established.connection,
        @intCast(fixed_io.now_ns),
    );

    const request_available =
        quic.one_rtt.testing.receiveStreamAvailableLen(
            &h3.established.connection,
            0,
        ).?;
    var oversized_value: [2048]u8 = undefined;
    @memset(&oversized_value, 'x');
    try std.testing.expectError(
        error.DatagramTooLarge,
        endpoint.acceptWithHeaders(handle, &.{.{
            .name = "x-oversized",
            .value = &oversized_value,
        }}),
    );
    try std.testing.expectEqual(@as(usize, 1), endpoint.pendingSessionCount());
    try std.testing.expect(h3.outbound_bodies.find(0) == null);
    try std.testing.expect(!h3.connect_datagrams.contains(0));

    const packet_number = h3.established.connection.next_packet_number;
    try std.testing.expectError(
        error.PacingLimited,
        endpoint.reject(handle, 403, &.{}),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 1), endpoint.pendingSessionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint.rejectedSessionCount());

    try std.testing.expectError(
        error.PacingLimited,
        endpoint.acceptWithHeaders(handle, &.{.{
            .name = "x-admission",
            .value = "literal",
        }}),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(
        request_available,
        quic.one_rtt.testing.receiveStreamAvailableLen(
            &h3.established.connection,
            0,
        ).?,
    );
    try std.testing.expectEqual(@as(usize, 1), endpoint.pendingSessionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint.sessionCount());
    try std.testing.expect(h3.outbound_bodies.find(0) == null);
    try std.testing.expect(!h3.connect_datagrams.contains(0));
    try std.testing.expectEqual(
        @as(usize, 0),
        h3.qpack_encode.pendingEncoderInstructions().len,
    );

    const timer = endpoint.h3.dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    _ = (try endpoint.h3.dispatcher.serviceNextTimerAt(
        timer.timer.deadline_ns,
    )) orelse
        return error.TestUnexpectedResult;
    const accepted = try endpoint.acceptWithHeaders(handle, &.{.{
        .name = "x-admission",
        .value = "literal",
    }});
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(@as(usize, 0), endpoint.pendingSessionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.sessionCount());
    try std.testing.expect(h3.outbound_bodies.find(0) != null);
    try std.testing.expect(h3.connect_datagrams.contains(0));
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(
            &h3.established.connection,
            0,
        ).?,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        h3.qpack_encode.pendingEncoderInstructions().len,
    );
    try std.testing.expectEqual(handle, accepted.handle);

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    var response_fin = false;
    for (0..3) |_| {
        var response_packet = try peer.receivePacketTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(100),
            },
        });
        defer response_packet.deinit(allocator);
        for (response_packet.frames) |frame| switch (frame) {
            .stream => |stream| if (stream.stream_id == 0) {
                try std.testing.expectEqual(
                    @as(u64, response_bytes.items.len),
                    stream.offset,
                );
                try response_bytes.appendSlice(allocator, stream.data);
                response_fin = stream.fin;
            },
            else => {},
        };
        if (response_bytes.items.len != 0) break;
    }
    if (response_bytes.items.len == 0) return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(bool, false),
        response_fin,
    );
    var empty_dynamic = http3.Qpack.DynamicTable.init(allocator, 0);
    defer empty_dynamic.deinit();
    var response_head = try http3.decodeResponseHeadWithDynamicTableAndOptions(
        allocator,
        response_bytes.items,
        settings,
        empty_dynamic,
        .{
            .request_method = "CONNECT",
            .extended_connect = true,
        },
    );
    defer response_head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response_head.status);
    try std.testing.expectEqual(
        @as(usize, 0),
        response_head.qpack_section_acknowledgments,
    );
}

test "WebTransport accepted session rejects a second CONNECT and stays usable" {
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
    const settings = webtransport.defaultSettings(.{
        .webtransport_max_sessions = 4,
    });
    try std.testing.expectEqual(
        @as(u64, 1),
        settings.webtransport_max_sessions,
    );
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-capacity-server",
            .peer_connection_id = "wt-capacity-client",
            .one_rtt = .{ .pacing_max_burst_packets = 1 },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);

    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 17;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }

    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-capacity-client",
        .peer_connection_id = "wt-capacity-server",
        .enable_pacing = false,
    });
    defer peer.deinit();

    var fixed_io = FixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &h3.established.connection,
        @intCast(fixed_io.now_ns),
    );

    var second_connect: std.ArrayList(u8) = .empty;
    defer second_connect.deinit(allocator);
    try (http3.Request{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/second",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport" },
            http3.capsule.protocol_header,
        },
    }).write(&second_connect, allocator);
    var associated: std.ArrayList(u8) = .empty;
    defer associated.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &associated,
        allocator,
        .init(0),
    );
    try associated.appendSlice(allocator, "alive");

    // The extra CONNECT and first-session traffic deliberately share one
    // encrypted packet. Only stream 4 is rejected; stream 8 remains routed to
    // the accepted session.
    try peer.send(&.{
        .{ .stream = .{
            .stream_id = 4,
            .data = second_connect.items,
        } },
        .{ .stream = .{
            .stream_id = 8,
            .data = associated.items,
            .fin = true,
        } },
    });
    var incoming = try h3.established.connection.receivePacket();
    defer incoming.deinit(allocator);
    try runtime.EndpointServer.testing.processAcceptedPacket(
        &accepted,
        &incoming,
    );
    try std.testing.expectEqual(
        @as(?u62, 4),
        accepted.request_rejection_pending,
    );
    try std.testing.expect(
        h3.established.connection.sendStreamStats(4).?.reset == null,
    );
    try std.testing.expect(
        h3.established.connection.recvStreamStats(4).?.stop_sending_sent == null,
    );
    try std.testing.expect(!h3.established.connection.closing());

    const retry = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, retry.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        retry.timer.kind,
    );
    var payload: [16]u8 = undefined;
    const accepted_event = (try runtime.EndpointServer.testing
        .pollAcceptedSessionEntry(&accepted, &payload)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(?u62, 4),
        accepted.request_rejection_pending,
    );
    try std.testing.expect(accepted_event == .stream);
    const stream_event = accepted_event.stream;
    try std.testing.expect(stream_event == .data);
    try std.testing.expectEqual(@as(u62, 8), stream_event.data.stream_id);
    try std.testing.expect(stream_event.data.fin);
    try std.testing.expectEqualStrings(
        "alive",
        payload[0..stream_event.data.bytes],
    );
    fixed_io.now_ns = @intCast(retry.timer.deadline_ns);
    try std.testing.expect(
        (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(
            &accepted,
            &payload,
        )) == null,
    );
    try std.testing.expect(accepted.request_rejection_pending == null);

    var saw_reset = false;
    var saw_stop = false;
    for (0..3) |_| {
        var response = try peer.receivePacketTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(100),
            },
        });
        defer response.deinit(allocator);
        for (response.frames) |frame| switch (frame) {
            .reset_stream => |reset| if (reset.stream_id == 4) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_rejected),
                    reset.application_error_code,
                );
                saw_reset = true;
            },
            .stop_sending => |stop| if (stop.stream_id == 4) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_rejected),
                    stop.application_error_code,
                );
                saw_stop = true;
            },
            else => {},
        };
        if (saw_reset and saw_stop) break;
    }
    try std.testing.expect(saw_reset);
    try std.testing.expect(saw_stop);
    try std.testing.expect(!peer.closing());
}

test "WebTransport endpoint poll mirrors automatic stream-credit retry timer" {
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
        [_]u8{0xe7} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-timer-server",
            .peer_connection_id = "wt-timer-client",
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 9;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);

    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    // Ownership moved to `accepted`; avoid the outer defer.
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &encoded,
        allocator,
        accepted.session_id,
    );
    try encoded.appendSlice(allocator, "terminal");
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 2,
            .data = encoded.items,
            .fin = true,
        } }},
        null,
        .not_ect,
    );

    var failed_send = ObservedBatchSend{
        .delegate = server_endpoint.io,
        .fail_after_prefix = 0,
    };
    server_endpoint.io = failed_send.io();
    defer server_endpoint.io = failed_send.delegate;

    var buffer: [32]u8 = undefined;
    const event = (try runtime.EndpointServer.testing
        .pollAcceptedSessionEntry(&accepted, &buffer)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(event == .stream);
    try std.testing.expect(event.stream == .data);
    try std.testing.expect(event.stream.data.fin);
    try std.testing.expectEqualStrings(
        "terminal",
        buffer[0..event.stream.data.bytes],
    );
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(!h3.established.connection.peerStreamClosed(2));

    const connection_timer = h3.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
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
    try std.testing.expect(h3.established.connection.peerStreamClosed(2));
}

test "WebTransport endpoint reads commit data and CLOSE before paced feedback" {
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
        [_]u8{0xf4} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var local_parameters = quic.practical_transport_parameters;
    local_parameters.initial_max_data = 128;
    local_parameters.initial_max_stream_data_bidi_remote = 64;
    local_parameters.initial_max_stream_data_uni = 64;
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-read-server",
            .peer_connection_id = "wt-read-client",
            .local_transport_parameters = local_parameters,
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
                .receive_window = 64,
                .stream_receive_window = 64,
            },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    try h3.outbound_bodies.reserveOpen(0);
    h3.outbound_bodies.appendOpenAssumeCapacity(
        0,
        quic.stream_state.SendState.init(0),
        null,
    );
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 17;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }

    var fixed_io = FixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &stream_bytes,
        allocator,
        accepted.session_id,
    );
    const prefix_len = stream_bytes.items.len;
    const payload = [_]u8{'s'} ** 40;
    try stream_bytes.appendSlice(allocator, &payload);
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 2,
            .data = stream_bytes.items,
            .fin = false,
        } }},
        1_000_000,
        .not_ect,
    );
    quic.one_rtt.testing.exhaustPacingAt(
        &h3.established.connection,
        @intCast(fixed_io.now_ns),
    );

    var buffer: [64]u8 = undefined;
    const stream_event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(&accepted, &buffer)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(stream_event == .stream and stream_event.stream == .data);
    try std.testing.expect(!stream_event.stream.data.fin);
    try std.testing.expectEqualStrings(&payload, buffer[0..stream_event.stream.data.bytes]);
    try std.testing.expectEqual(@as(u64, payload.len), accepted.streams.get(2).?.bytes_received);
    try std.testing.expectEqual(@as(usize, 0), quic.one_rtt.testing.receiveStreamAvailableLen(&h3.established.connection, 2).?);
    try std.testing.expectEqual(prefix_len + payload.len, stream_bytes.items.len);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(h3.established.connection.receive_credit_retry_deadline_ns != null);
    for (0..16) |_| {
        if (h3.established.connection.receive_credit_retry_deadline_ns == null) break;
        const timer = dispatcher.nextTimerDeadline().?;
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse return error.TestUnexpectedResult;
    }
    try std.testing.expect(h3.established.connection.receive_credit_retry_deadline_ns == null);
    try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(&accepted, &buffer)) == null);

    var close_capsule: [4 + session_control.max_close_reason + 16]u8 =
        undefined;
    const capsule = try session_control.writeCloseInto(
        &close_capsule,
        89,
        "paced control credit rollback",
    );
    var control_bytes: [4 + session_control.max_close_reason + 32]u8 =
        undefined;
    const control_len = try writeDataFrame(&control_bytes, capsule);
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = control_bytes[0..control_len],
            .fin = true,
        } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    quic.one_rtt.testing.exhaustPacingAt(
        &h3.established.connection,
        @intCast(fixed_io.now_ns),
    );
    // CLOSE is observed immediately; response FIN and receive feedback remain
    // pending transport work and cannot hide its original code or reason.
    try std.testing.expectError(error.InvalidSessionState, accepted.openBidirectionalStream());
    var close_event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(&accepted, &buffer)) orelse return error.TestUnexpectedResult;
    defer close_event.deinit(allocator);
    try std.testing.expect(close_event == .session and close_event.session == .closed);
    try std.testing.expectEqual(@as(u32, 89), close_event.session.closed.code);
    try std.testing.expectEqualStrings("paced control credit rollback", close_event.session.closed.reason);
    try std.testing.expect(accepted.control.state.closed and accepted.control.terminal_reported);
    try std.testing.expect(accepted.close_response_pending);
    try std.testing.expectEqual(@as(u64, control_len), h3.established.connection.recvStreamStats(0).?.bytes_read);
    try std.testing.expect(h3.established.connection.receive_credit_retry_deadline_ns != null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    for (0..16) |_| {
        if (h3.established.connection.receive_credit_retry_deadline_ns == null) break;
        const timer = dispatcher.nextTimerDeadline().?;
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse return error.TestUnexpectedResult;
    }
    try std.testing.expect(h3.established.connection.receive_credit_retry_deadline_ns == null);
    try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(&accepted, &buffer)) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
}

test "WebTransport endpoint poll refreshes timers before returning an error" {
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
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        .{ .ip4 = .loopback(9105) },
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-error-server",
            .peer_connection_id = "wt-error-client",
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 10;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }

    // Leave a Capsule type varint incomplete at a clean HTTP/3 DATA-frame
    // boundary, then deliver FIN. Polling must report InvalidCapsule. A PING
    // submitted since registration supplies unmirrored recovery work whose
    // PTO must still reach the endpoint before that error escapes.
    try std.testing.expect((try accepted.control.feed(&.{
        0x00,
        0x01,
        0x40,
    })) == null);
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        0,
        &.{.{ .stream = .{
            .stream_id = accepted.session_id.value,
            .data = &.{},
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try h3.established.connection.send(&.{.{ .ping = {} }});
    try std.testing.expect(h3.established.connection.nextTimerDeadline() != null);
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);

    var buffer: [1]u8 = undefined;
    try std.testing.expectError(
        error.InvalidCapsule,
        runtime.EndpointServer.testing.pollAcceptedSessionEntry(
            &accepted,
            &buffer,
        ),
    );
    const endpoint_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, endpoint_timer.connection_id);
    // The malformed CONNECT also schedules RESET_STREAM/STOP_SENDING. Mirror
    // the connection's current aggregate recovery timer after that submission.
    try std.testing.expectEqual(h3.established.connection.nextTimerDeadline().?, endpoint_timer.timer);
    try std.testing.expect(accepted.control.capsule_error_rejected);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.message_error),
        h3.established.connection.sendStreamStats(0).?.reset.?.application_error_code,
    );
}

test "WebTransport endpoint close failure still schedules expiry" {
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
        [_]u8{0xed} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        .{ .ip4 = .loopback(9106) },
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-close-server",
            .peer_connection_id = "wt-close-client",
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 11;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);

    var failed_send = ObservedBatchSend{
        .delegate = server_endpoint.io,
        .fail_after_prefix = 0,
    };
    server_endpoint.io = failed_send.io();
    defer server_endpoint.io = failed_send.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        accepted.closeConnection(77, "socket failed"),
    );
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(h3.established.connection.closing());
    const connection_timer = h3.established.connection
        .nextTimerDeadline() orelse return error.TestUnexpectedResult;
    const endpoint_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, endpoint_timer.connection_id);
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.close,
        endpoint_timer.timer.kind,
    );

    server_endpoint.io = failed_send.delegate;
    _ = (try dispatcher.serviceNextTimerAt(
        endpoint_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(h3.established.connection.closed());
}

test "WebTransport endpoint stream write leaves UDP receive to dispatcher" {
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
        [_]u8{0xee} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var peer_parameters = quic.practical_transport_parameters;
    // Session ID zero has a three-byte bidirectional association prefix. Give
    // the server exactly that much initial stream and connection credit.
    peer_parameters.initial_max_data = 3;
    peer_parameters.initial_max_stream_data_bidi_remote = 3;
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-write-server",
            .peer_connection_id = "wt-write-client",
            .peer_transport_parameters = peer_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        1,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 12;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }
    const stream_id = try accepted.openBidirectionalStream();
    try std.testing.expectEqual(@as(u62, 1), stream_id);

    // Queue credit before the write. A blocking per-connection writer would
    // steal this datagram from the shared socket and succeed in the same call.
    // The endpoint writer must return with zero application progress instead.
    try quic.one_rtt.sendFrames(
        &peer_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = "wt-write-server",
            .packet_number = 0,
            .frames = &.{
                .{ .max_data = .{ .maximum_data = 4 } },
                .{ .max_stream_data = .{
                    .stream_id = stream_id,
                    .maximum_stream_data = 4,
                } },
            },
        },
    );
    try std.testing.expectError(
        error.FlowControlBlocked,
        accepted.sendStream(stream_id, "x", true),
    );
    const stream = accepted.streams.get(stream_id) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);

    var counts: [1]usize = undefined;
    const batch_result = try accepted.writeStreams(
        &.{.{ .stream_id = stream_id, .data = "x" }},
        &counts,
    );
    try std.testing.expectEqual(@as(usize, 0), batch_result.progressed);
    try std.testing.expect(batch_result.send_error == null);
    try std.testing.expectEqual(@as(usize, 0), counts[0]);
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    const blocked_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, blocked_timer.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pto,
        blocked_timer.timer.kind,
    );

    var credit = try dispatcher.receive(
        &.{quic.Version.version_1.wireValue()},
    );
    defer credit.deinit(allocator);
    try std.testing.expect(credit == .packet);
    try std.testing.expectEqual(handle, credit.packet.connection_handle);
    try std.testing.expectEqual(
        @as(usize, 1),
        try accepted.writeStreamSlices(
            stream_id,
            &.{ &.{}, "x", &.{} },
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), stream.bytes_sent);
    try accepted.finishStream(stream_id);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport endpoint control and datagram sends do not wait for pacing" {
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
        [_]u8{0xef} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-control-server",
            .peer_connection_id = "wt-control-client",
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    try h3.outbound_bodies.reserveOpen(0);
    h3.outbound_bodies.appendOpenAssumeCapacity(
        0,
        quic.stream_state.SendState.init(0),
        null,
    );
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        1,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 13;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }
    const reset_stream_id = try accepted.openBidirectionalStream();
    const stopped_stream_id: u62 = 4;
    _ = try accepted.streams.registerPeer(
        stopped_stream_id,
        .bidirectional,
    );
    const close_send_id: u62 = 15;
    _ = try accepted.streams.registerLocal(
        close_send_id,
        .unidirectional,
    );
    const close_receive_id: u62 = 14;
    const close_receive = try accepted.streams.registerPeer(
        close_receive_id,
        .unidirectional,
    );

    // Freeze std.Io's awake clock so a blocking pacing loop cannot make
    // progress. The one-attempt endpoint methods must return PacingLimited
    // without ever invoking the wrapped sleep operation.
    var fixed_io = FixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;

    const fill = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = &.{} } },
        .{ .padding = .{ .len = 1150 } },
    };
    try h3.established.connection.sendAt(&fill, 1_000_000);
    const next_packet_number = h3.established.connection.next_packet_number;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.resetStream(reset_stream_id, 41),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(@as(usize, 1), fixed_io.send_calls);
    try std.testing.expectEqual(
        next_packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expect(
        accepted.streams.get(reset_stream_id).?.send_reset == null,
    );
    try std.testing.expect(
        h3.established.connection.sendStreamStats(reset_stream_id).?.reset ==
            null,
    );
    const reset_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, reset_timer.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        reset_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(reset_timer.timer.deadline_ns);
    const reset_timer_event = (try dispatcher.serviceNextTimerAt(
        reset_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        reset_timer_event.timer.kind,
    );
    try accepted.resetStream(reset_stream_id, 41);
    try std.testing.expect(
        accepted.streams.get(reset_stream_id).?.send_reset != null,
    );

    const reset_packet_number = h3.established.connection.next_packet_number;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.stopStream(stopped_stream_id, 42),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        reset_packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expect(
        accepted.streams.get(stopped_stream_id).?.stop_sent == null,
    );
    try std.testing.expect(
        h3.established.connection.recvStreamStats(stopped_stream_id).?
            .stop_sending_sent == null,
    );

    const stop_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, stop_timer.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        stop_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(stop_timer.timer.deadline_ns);
    const stop_timer_event = (try dispatcher.serviceNextTimerAt(
        stop_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        stop_timer_event.timer.kind,
    );
    try accepted.stopStream(stopped_stream_id, 42);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(@as(usize, 3), fixed_io.send_calls);
    try std.testing.expect(
        accepted.streams.get(stopped_stream_id).?.stop_sent != null,
    );

    const before_datagram = accepted.stats();
    const datagram_packet_number =
        h3.established.connection.next_packet_number;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.sendDatagram("single-attempt"),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        datagram_packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(
        before_datagram.datagrams_sent,
        accepted.stats().datagrams_sent,
    );
    const datagram_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        datagram_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(datagram_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        datagram_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.sendDatagram("single-attempt");
    try std.testing.expectEqual(
        before_datagram.datagrams_sent + 1,
        accepted.stats().datagrams_sent,
    );

    const bounded_deadline = std.Io.Clock.Timestamp.fromNow(
        server_endpoint.io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    try std.testing.expectError(
        error.PacingLimited,
        accepted.trySendDatagramWithDeadline(
            "bounded-attempt",
            bounded_deadline,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        before_datagram.datagrams_sent + 1,
        accepted.stats().datagrams_sent,
    );
    const bounded_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        bounded_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(bounded_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        bounded_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.trySendDatagramWithDeadline(
        "bounded-attempt",
        bounded_deadline,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        before_datagram.datagrams_sent + 2,
        accepted.stats().datagrams_sent,
    );

    var datagram_batch_count: usize = 99;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.sendDatagrams(
            &.{ "batch-one", "batch-two" },
            &datagram_batch_count,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), datagram_batch_count);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        before_datagram.datagrams_sent + 2,
        accepted.stats().datagrams_sent,
    );
    const datagram_batch_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        datagram_batch_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(datagram_batch_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        datagram_batch_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.sendDatagrams(
        &.{ "batch-one", "batch-two" },
        &datagram_batch_count,
    );
    // One pacing slot admits one QUIC packet. Both small logical DATAGRAMs
    // fit in that packet, so the committed prefix includes both payloads.
    try std.testing.expectEqual(@as(usize, 2), datagram_batch_count);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        before_datagram.datagrams_sent + 4,
        accepted.stats().datagrams_sent,
    );

    const body_offset = h3.outbound_bodies.find(0).?.send.next_offset;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.sendSessionData("not-sent", false),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        body_offset,
        h3.outbound_bodies.find(0).?.send.next_offset,
    );
    const body_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, body_timer.connection_id);
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        body_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(body_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        body_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    var body_sent = false;
    for (0..4) |_| {
        accepted.sendSessionDataSlices(
            &.{ "unknown-", &.{}, "capsule" },
            false,
        ) catch |err| switch (err) {
            error.PacingLimited => {
                const retry_timer = dispatcher.nextTimerDeadline() orelse
                    return error.TestUnexpectedResult;
                try std.testing.expectEqual(
                    quic.one_rtt.TimerDeadlineKind.pacing,
                    retry_timer.timer.kind,
                );
                fixed_io.now_ns = @intCast(retry_timer.timer.deadline_ns);
                _ = (try dispatcher.serviceNextTimerAt(
                    retry_timer.timer.deadline_ns,
                )) orelse return error.TestUnexpectedResult;
                continue;
            },
            else => return err,
        };
        body_sent = true;
        break;
    }
    try std.testing.expect(body_sent);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(
        h3.outbound_bodies.find(0).?.send.next_offset > body_offset,
    );

    const before_drain_offset = h3.outbound_bodies.find(0).?.send.next_offset;
    try std.testing.expectError(error.PacingLimited, accepted.drain());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(!accepted.control.local_drain_sent);
    try std.testing.expectEqual(
        before_drain_offset,
        h3.outbound_bodies.find(0).?.send.next_offset,
    );
    const drain_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        drain_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(drain_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        drain_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.drain();
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(accepted.control.local_drain_sent);
    try std.testing.expect(
        h3.outbound_bodies.find(0).?.send.next_offset > before_drain_offset,
    );

    // Keep the earlier bidi cancellation fixtures out of close cleanup so
    // this section has exactly one send-only and one receive-only stream.
    accepted.streams.get(reset_stream_id).?.peer_fin = true;
    accepted.streams.get(stopped_stream_id).?.local_fin = true;
    const close_body_offset =
        h3.outbound_bodies.find(0).?.send.next_offset;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.close(71, "single-attempt close"),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(!accepted.control.local_close_sent);
    try std.testing.expectEqual(
        close_body_offset,
        h3.outbound_bodies.find(0).?.send.next_offset,
    );

    const close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        close_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(close_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        close_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.close(71, "single-attempt close");
    try std.testing.expect(accepted.control.local_close_sent);
    try std.testing.expect(accepted.control.state.closed);
    try std.testing.expect(h3.outbound_bodies.find(0) == null);
    try std.testing.expect(
        accepted.streams.get(close_send_id).?.send_reset == null,
    );
    try std.testing.expect(close_receive.stop_sent == null);

    // Each later invocation advances at most one stream-control packet. A
    // paced failure commits neither registry state nor a packet number.
    const cleanup_packet_number =
        h3.established.connection.next_packet_number;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.close(71, "ignored after capsule commit"),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        cleanup_packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expect(
        accepted.streams.get(close_send_id).?.send_reset == null,
    );
    const reset_close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.now_ns = @intCast(reset_close_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        reset_close_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.close(71, "ignored after capsule commit");
    try std.testing.expect(
        accepted.streams.get(close_send_id).?.send_reset != null,
    );
    try std.testing.expect(close_receive.stop_sent == null);

    try std.testing.expectError(
        error.PacingLimited,
        accepted.close(71, "ignored after capsule commit"),
    );
    const stop_close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.now_ns = @intCast(stop_close_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        stop_close_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.close(71, "ignored after capsule commit");
    try std.testing.expect(close_receive.stop_sent != null);
    const send_calls_after_cleanup = fixed_io.send_calls;
    try accepted.close(71, "ignored after capsule commit");
    try std.testing.expectEqual(
        send_calls_after_cleanup,
        fixed_io.send_calls,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
}

test "WebTransport endpoint reports peer close before paced response FIN" {
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
        [_]u8{0xf0} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-peer-close-server",
            .peer_connection_id = "wt-peer-close-client",
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.outbound_bodies.reserveOpen(0);
    h3.outbound_bodies.appendOpenAssumeCapacity(
        0,
        quic.stream_state.SendState.init(0),
        null,
    );
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        1,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 14;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }

    var fixed_io = FixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;

    try h3.established.connection.sendAt(
        &.{.{ .padding = .{ .len = 1160 } }},
        1_000_000,
    );
    var close_capsule: [4 + session_control.max_close_reason + 16]u8 =
        undefined;
    const capsule = try session_control.writeCloseInto(
        &close_capsule,
        88,
        "peer done",
    );
    var data_frame: [4 + session_control.max_close_reason + 32]u8 = undefined;
    const data_len = try writeDataFrame(&data_frame, capsule);
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = data_frame[0..data_len],
            .fin = true,
        } }},
        1_000_000,
        .not_ect,
    );

    var buffer: [1]u8 = undefined;
    var event = (try runtime.EndpointServer.testing
        .pollAcceptedSessionEntry(&accepted, &buffer)) orelse
        return error.TestUnexpectedResult;
    defer event.deinit(allocator);
    try std.testing.expect(event == .session);
    try std.testing.expect(event.session == .closed);
    try std.testing.expectEqual(@as(u32, 88), event.session.closed.code);
    try std.testing.expectEqualStrings(
        "peer done",
        event.session.closed.reason,
    );
    try std.testing.expect(accepted.control.terminal_reported);
    try std.testing.expect(accepted.close_response_pending);
    try std.testing.expect(!accepted.control.local_close_sent);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);

    try std.testing.expect(
        (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(
            &accepted,
            &buffer,
        )) == null,
    );
    try std.testing.expect(accepted.close_response_pending);
    try std.testing.expect(!accepted.control.local_close_sent);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        timer.timer.kind,
    );

    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(
        (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(
            &accepted,
            &buffer,
        )) == null,
    );
    try std.testing.expect(!accepted.close_response_pending);
    try std.testing.expect(accepted.control.local_close_sent);
    try std.testing.expect(h3.outbound_bodies.find(0) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
}

test "WebTransport endpoint stream credit operations do not wait for pacing" {
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
        [_]u8{0xf1} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var local_parameters = quic.practical_transport_parameters;
    local_parameters.initial_max_streams_uni = 4;
    var peer_parameters = quic.practical_transport_parameters;
    peer_parameters.initial_max_streams_bidi = 0;
    peer_parameters.initial_max_streams_uni = 3;
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-credit-server",
            .peer_connection_id = "wt-credit-client",
            .local_transport_parameters = local_parameters,
            .peer_transport_parameters = peer_parameters,
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    inline for (.{ @as(u64, 3), @as(u64, 7), @as(u64, 11) }) |expected| {
        try std.testing.expectEqual(
            expected,
            try h3.established.connection.openUnidirectionalStream(),
        );
    }
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        1,
        15,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    const peer_stream_id: u62 = 14;
    _ = try streams.registerPeer(peer_stream_id, .unidirectional);
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        0,
        &.{.{ .stream = .{
            .stream_id = peer_stream_id,
            .data = "x",
            .fin = true,
        } }},
        1_000_000,
        .not_ect,
    );
    try h3.established.connection.releaseReceivedCapacity(peer_stream_id, 1);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 15;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    streams_owned = false;
    defer {
        accepted.control.deinit();
        accepted.streams.deinit();
    }

    var fixed_io = FixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;

    try h3.established.connection.sendAt(
        &.{.{ .padding = .{ .len = 1160 } }},
        1_000_000,
    );
    try std.testing.expectError(
        error.PacingLimited,
        accepted.openBidirectionalStream(),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(u64, 1),
        h3.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expect(accepted.streams.get(1) == null);
    const bidi_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        bidi_timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(bidi_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        bidi_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectError(
        error.StreamLimitExceeded,
        accepted.openBidirectionalStream(),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        h3.established.connection.nextLocalBidirectionalStreamId(),
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        1,
        &.{.{ .max_streams_bidi = .{ .maximum_streams = 1 } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(u62, 1),
        try accepted.openBidirectionalStream(),
    );

    try std.testing.expectError(
        error.PacingLimited,
        accepted.openUnidirectionalStream(),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(u64, 15),
        h3.established.connection.nextLocalUnidirectionalStreamId(),
    );
    try std.testing.expect(accepted.streams.get(15) == null);
    const uni_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.now_ns = @intCast(uni_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        uni_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectError(
        error.StreamLimitExceeded,
        accepted.openUnidirectionalStream(),
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        2,
        &.{.{ .max_streams_uni = .{ .maximum_streams = 4 } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(u62, 15),
        try accepted.openUnidirectionalStream(),
    );

    try std.testing.expectError(
        error.PacingLimited,
        accepted.releaseCompletedPeerStream(peer_stream_id),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(
        !h3.established.connection.peerStreamClosed(peer_stream_id),
    );
    const release_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.now_ns = @intCast(release_timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(
        release_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(
        try accepted.releaseCompletedPeerStream(peer_stream_id),
    );
    try std.testing.expect(
        h3.established.connection.peerStreamClosed(peer_stream_id),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
}

test "WebTransport dispatcher client defers terminal cleanup pacing" {
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
        [_]u8{0xf2} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "wt-close-client",
                .peer_connection_id = "wt-close-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{ .local_settings = settings },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    try std.testing.expectEqual(
        @as(u64, 0),
        try h3.established.connection.openStream(),
    );
    try h3.request_lifecycle.open(0, "CONNECT", true);
    try h3.outbound_bodies.reserveOpen(0);
    h3.outbound_bodies.appendOpenAssumeCapacity(
        0,
        quic.stream_state.SendState.init(0),
        null,
    );
    try h3.sendRequestBody(0, "x", false);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .client,
        settings,
        settings,
        8,
        4,
        14,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    _ = try streams.registerPeer(1, .bidirectional);
    try quic.one_rtt.testing.applyReceivedFrames(
        &h3.established.connection,
        0,
        &.{.{ .stream = .{ .stream_id = 1, .data = "x" } }},
        4_000_000,
        .not_ect,
    );

    var response = http3.DecodedResponseHead{
        .status = 200,
        .headers = &.{},
        .content_length = null,
        .body_allowed = true,
        .consumed = 0,
        .qpack_section_acknowledgments = 0,
    };
    var response_owned = true;
    defer if (response_owned) response.deinit(allocator);
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 26;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var session = runtime.HandshakeClientSession{
        .h3 = h3,
        .session_id = .init(0),
        .response = response,
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
        .dispatcher = &dispatcher,
        .dispatcher_handle = handle,
    };
    h3_owned = false;
    streams_owned = false;
    response_owned = false;
    defer session.deinit();
    defer _ = dispatcher.unregisterConnection(handle) catch false;
    try dispatcher.replaceConnection(
        handle,
        &session.h3.established.connection,
    );

    var close_capsule: [4 + session_control.max_close_reason + 16]u8 =
        undefined;
    const capsule = try session_control.writeCloseInto(
        &close_capsule,
        91,
        "client peer close",
    );
    var framed: [4 + session_control.max_close_reason + 32]u8 = undefined;
    const framed_len = try writeDataFrame(&framed, capsule);

    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 4_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &session.h3.established.connection,
        @intCast(fixed_io.now_ns),
    );
    const drain_packet_number =
        session.h3.established.connection.next_packet_number;
    try std.testing.expectError(error.PacingLimited, session.drain());
    try std.testing.expect(!session.control.local_drain_sent);
    try std.testing.expectEqual(
        drain_packet_number,
        session.h3.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    var timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try session.drain();
    try std.testing.expect(session.control.local_drain_sent);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);

    // Exercise advisory DRAIN while the Session is open, then receive the
    // terminal peer CLOSE/FIN and defer its response cleanup independently.
    try quic.one_rtt.testing.applyReceivedFrames(
        &session.h3.established.connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = framed[0..framed_len],
            .fin = true,
        } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    quic.one_rtt.testing.exhaustPacingAt(
        &session.h3.established.connection,
        @intCast(fixed_io.now_ns),
    );

    const event = (try session.pollSessionEvent()) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 91), event.closed.code);
    try std.testing.expectEqualStrings("client peer close", event.closed.reason);
    try std.testing.expect(session.close_response_pending);
    try std.testing.expect(!session.control.local_close_sent);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);

    const packet_number = session.h3.established.connection.next_packet_number;
    try std.testing.expect((try session.pollSessionEvent()) == null);
    try std.testing.expect(session.close_response_pending);
    try std.testing.expectEqual(
        packet_number,
        session.h3.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);

    timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect((try session.pollSessionEvent()) == null);
    try std.testing.expect(!session.close_response_pending);
    try std.testing.expect(session.control.local_close_sent);
    try std.testing.expect(session.h3.outbound_bodies.find(0) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);

    // Each later poll terminates at most one associated direction. Both the
    // RESET_STREAM and STOP_SENDING are paced and remain retryable.
    inline for (.{ "reset", "stop" }) |stage| {
        try std.testing.expect((try session.pollSessionEvent()) == null);
        try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
        timer = dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            quic.one_rtt.TimerDeadlineKind.pacing,
            timer.timer.kind,
        );
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
            return error.TestUnexpectedResult;
        try std.testing.expect((try session.pollSessionEvent()) == null);
        const state = session.streams.get(1) orelse
            return error.TestUnexpectedResult;
        if (std.mem.eql(u8, stage, "reset")) {
            try std.testing.expect(state.send_reset != null);
        } else {
            try std.testing.expect(state.stop_sent != null);
        }
        try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    }
}

test "WebTransport client handshake and CONNECT share one socket owner" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});
    const limits = runtime.Limits{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } } };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = "wt-source-server",
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.http3.quic,
    );
    defer client_endpoint.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{"wt-source-client"},
        server.address(),
        64,
    );
    defer inbox.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerPendingHandshake(1, &inbox);

    const ServerTask = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.receiveSessionRequest() catch |err| {
                self.err = err;
                return;
            };
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            if (!std.mem.eql(u8, pending.path(), "/source")) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            var accepted = pending.accept() catch |err| {
                self.err = err;
                return;
            };
            pending_owned = false;
            defer accepted.deinit();
            accepted.close(73, "source-close") catch |err| {
                self.err = err;
            };
        }
    };
    const ClientTask = struct {
        endpoint: *quic.runtime.Endpoint,
        inbox: *quic.handshake_inbox.Inbox,
        server: std.Io.net.IpAddress,
        settings: http3.Settings,
        done: std.atomic.Value(bool) = .init(false),
        pending: ?runtime.PendingHandshakeConnect = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.pending = runtime.HandshakeClientSession.beginConnectFrom(
                self.endpoint,
                self.inbox.datagramSource(),
                self.server,
                .{
                    .authority = "localhost",
                    .path = "/source",
                    .limits = limits,
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = "wt-source-dispatch",
                            .local_connection_id = "wt-source-client",
                            .server_name = "localhost",
                            .random = [_]u8{0xa3} ** 32,
                            .x25519_secret_key = [_]u8{0xa4} ** 32,
                            .handshake_recovery = .{
                                .initial_pto_ms = 20,
                                .max_pto_ms = 40,
                                .max_duration_ms = 2_000,
                            },
                        },
                        .session = .{ .local_settings = self.settings },
                    },
                },
            ) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };

    var server_task = ServerTask{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerTask.run,
        .{&server_task},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var client_task = ClientTask{
        .endpoint = &client_endpoint,
        .inbox = &inbox,
        .server = server.address(),
        .settings = settings,
    };
    const client_thread = try std.Thread.spawn(
        .{},
        ClientTask.run,
        .{&client_task},
    );

    var owner_err: ?anyerror = null;
    owner: while (!client_task.done.load(.acquire)) {
        const datagram = client_endpoint.receiveBytesTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(20),
            },
        }) catch |err| switch (err) {
            error.Timeout => continue,
            else => {
                owner_err = err;
                break :owner;
            },
        };
        var event = dispatcher.dispatch(datagram) catch |err| {
            owner_err = err;
            break :owner;
        };
        defer event.deinit(allocator);
        switch (event) {
            .pending_handshake, .consumed => {},
            else => {
                owner_err = error.TestUnexpectedResult;
                break :owner;
            },
        }
    }
    if (!client_task.done.load(.acquire)) inbox.close();
    client_thread.join();
    if (owner_err) |err| return err;
    if (client_task.err) |err| return err;
    var pending = client_task.pending orelse return error.TestUnexpectedResult;
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();

    // Promotion closes the handshake inbox and transfers any short-header
    // CONNECT response that raced with the worker's completion into the
    // dispatcher's established-packet queue. No packet can fall into an
    // unregister/register gap.
    try dispatcher.promotePendingHandshake(1, 1, pending.connection());
    try std.testing.expect((try pending.pollConnect()) == null);
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var completed: ?runtime.HandshakeConnectAttempt = null;
    while (completed == null) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try std.testing.expectEqual(
                    @as(usize, 1),
                    routed.connection_handle,
                );
                try pending.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
                if (try pending.pollConnectForDispatcher(
                    &dispatcher,
                    1,
                )) |attempt| {
                    pending_owned = false;
                    completed = attempt;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    var attempt = completed.?;
    var session: runtime.HandshakeClientSession = undefined;
    try attempt.requireAcceptedForDispatcher(
        &dispatcher,
        1,
        &session,
    );
    var session_owned = true;
    defer if (session_owned) session.deinit();
    var closed = false;
    while (!closed) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try session.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
                if (try session.pollSessionEvent()) |session_event| {
                    if (session_event != .closed) {
                        return error.TestUnexpectedResult;
                    }
                    try std.testing.expectEqual(
                        @as(u32, 73),
                        session_event.closed.code,
                    );
                    try std.testing.expectEqualStrings(
                        "source-close",
                        session_event.closed.reason,
                    );
                    closed = true;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    session.deinit();
    session_owned = false;
    try std.testing.expectEqual(@as(usize, 0), dispatcher.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_task.err) |err| return err;
}

test "WebTransport shared-endpoint client handshake has a total timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{"wt-timeout-client"},
        silent.address(),
        1,
    );
    defer inbox.deinit();

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.beginConnectFromWithTimeout(
            &endpoint,
            inbox.datagramSource(),
            silent.address(),
            .{
                .authority = "localhost",
                .path = "/timeout",
                .h3 = .{ .handshake = .{
                    .original_destination_connection_id = "wt-timeout-origin",
                    .local_connection_id = "wt-timeout-client",
                    .handshake_recovery = .{
                        .initial_pto_ms = 1_000,
                        .max_pto_ms = 4_000,
                        .max_retries = 3,
                    },
                } },
            },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
    try std.testing.expectError(
        error.Timeout,
        runtime.HandshakeClientSession.beginConnectFromWithTimeout(
            &endpoint,
            inbox.datagramSource(),
            silent.address(),
            .{
                .authority = "localhost",
                .path = "/timeout",
                .h3 = .{ .handshake = .{
                    .original_destination_connection_id = "wt-timeout-origin",
                    .local_connection_id = "wt-timeout-client",
                } },
            },
            .zero,
        ),
    );
}

test "WebTransport sessions poll dispatcher-routed stream and datagram state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_a_cid = "wt-client-a";
    const client_b_cid = "wt-client-b";
    const server_a_cid = "wt-server-a";
    const server_b_cid = "wt-server-b";
    const client_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const client_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    const server_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    const server_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    const h3_options = http3.runtime.HandshakeSessionOptions{
        .local_settings = settings,
        .max_stream_frame_data = 1024,
    };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_a_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_a_endpoint.deinit();
    var client_b_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_b_endpoint.deinit();

    var server_a_h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_a_endpoint.address(),
        h3_options,
        .{
            .receive_keys = client_a_keys,
            .send_keys = server_a_keys,
            .local_connection_id = server_a_cid,
            .peer_connection_id = client_a_cid,
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
        },
    );
    var server_a_h3_owned = true;
    defer if (server_a_h3_owned) server_a_h3.deinit();
    var server_b_h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_b_endpoint.address(),
        h3_options,
        .{
            .receive_keys = client_b_keys,
            .send_keys = server_b_keys,
            .local_connection_id = server_b_cid,
            .peer_connection_id = client_b_cid,
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
        },
    );
    var server_b_h3_owned = true;
    defer if (server_b_h3_owned) server_b_h3.deinit();

    var streams_a = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_a_owned = true;
    defer if (streams_a_owned) streams_a.deinit();
    var streams_b = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_b_owned = true;
    defer if (streams_b_owned) streams_b.deinit();

    var session_a = runtime.AcceptedHandshakeSession{
        .h3 = server_a_h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams_a,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    server_a_h3_owned = false;
    streams_a_owned = false;
    defer {
        session_a.control.deinit();
        session_a.streams.deinit();
        session_a.h3.deinit();
    }
    var session_b = runtime.AcceptedHandshakeSession{
        .h3 = server_b_h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams_b,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    server_b_h3_owned = false;
    streams_b_owned = false;
    defer {
        session_b.control.deinit();
        session_b.streams.deinit();
        session_b.h3.deinit();
    }
    // These sessions are constructed after the CONNECT exchange boundary so
    // seed the peer SETTINGS that acceptance has already validated. The test
    // then focuses exclusively on post-admission dispatcher routing.
    session_a.h3.control.settings.markSent(settings);
    session_a.h3.control.settings.markReceived(settings);
    session_b.h3.control.settings.markSent(settings);
    session_b.h3.control.settings.markReceived(settings);
    try session_a.h3.connect_datagrams.register(0);
    try session_b.h3.connect_datagrams.register(0);

    var client_a = try quic.one_rtt.Connection.init(&client_a_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_a_keys,
        .send_keys = client_a_keys,
        .local_connection_id = client_a_cid,
        .peer_connection_id = server_a_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client_a.deinit();
    var client_b = try quic.one_rtt.Connection.init(&client_b_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_b_keys,
        .send_keys = client_b_keys,
        .local_connection_id = client_b_cid,
        .peer_connection_id = server_b_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client_b.deinit();

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &session_a.h3.established.connection);
    try dispatcher.registerConnection(2, &session_b.h3.established.connection);

    var prefix_a: [16]u8 = undefined;
    var prefix_b: [16]u8 = undefined;
    const header_a = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_a,
        .init(0),
    );
    const header_b = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_b,
        .init(0),
    );
    const stream_a = [_]quic.Frame{ .{ .stream = .{
        .stream_id = 4,
        .data = header_a,
    } }, .{ .stream = .{
        .stream_id = 4,
        .offset = header_a.len,
        .data = "stream-a",
        .fin = true,
    } } };
    const stream_b = [_]quic.Frame{ .{ .stream = .{
        .stream_id = 4,
        .data = header_b,
    } }, .{ .stream = .{
        .stream_id = 4,
        .offset = header_b.len,
        .data = "stream-b",
        .fin = true,
    } } };
    try client_b.send(&stream_b);
    try client_a.send(&stream_a);
    try sendDatagram(&client_b, .init(0), "datagram-b");
    try sendDatagram(&client_a, .init(0), "datagram-a");
    var drain_a_storage: [16]u8 = undefined;
    const drain_a = try session_control.writeDrainInto(&drain_a_storage);
    var framed_a: [32]u8 = undefined;
    const framed_a_len = try writeDataFrame(
        &framed_a,
        drain_a,
    );
    const control_a = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = framed_a[0..framed_a_len],
    } }};
    try client_a.send(&control_a);

    var saw_stream_a = false;
    var saw_stream_b = false;
    var saw_datagram_a = false;
    var saw_datagram_b = false;
    var saw_drain_a = false;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!saw_stream_a or !saw_stream_b or
        !saw_datagram_a or !saw_datagram_b or !saw_drain_a)
    {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                const session = switch (routed.connection_handle) {
                    1 => &session_a,
                    2 => &session_b,
                    else => return error.TestUnexpectedResult,
                };
                try session.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(
                    routed.connection_handle,
                );
                if (try session.pollCompleteStream()) |stream_value| {
                    var stream = stream_value;
                    defer stream.deinit();
                    const expected = if (routed.connection_handle == 1)
                        "stream-a"
                    else
                        "stream-b";
                    try std.testing.expectEqualStrings(
                        expected,
                        stream.payload,
                    );
                    if (routed.connection_handle == 1)
                        saw_stream_a = true
                    else
                        saw_stream_b = true;
                }
                if (try session.pollDatagram()) |datagram_value| {
                    var datagram = datagram_value;
                    defer datagram.deinit(allocator);
                    const expected = if (routed.connection_handle == 1)
                        "datagram-a"
                    else
                        "datagram-b";
                    try std.testing.expectEqualStrings(
                        expected,
                        datagram.datagram.payload,
                    );
                    if (routed.connection_handle == 1)
                        saw_datagram_a = true
                    else
                        saw_datagram_b = true;
                }
                if (try session.pollSessionEvent()) |control| {
                    try std.testing.expectEqual(
                        @as(usize, 1),
                        routed.connection_handle,
                    );
                    try std.testing.expect(control == .draining);
                    saw_drain_a = true;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
}

test "WebTransport client polls a dispatcher-injected packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = "wt-routed-client";
    const server_cid = "wt-routed-server";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    const limits = http3.runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer client_endpoint.deinit();
    var pending = try runtime.HandshakeClientSession.beginEstablishedConnect(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = transport_parameters,
                .peer_transport_parameters = transport_parameters,
                .one_rtt = .{ .enable_pacing = false },
            },
        ),
        .{
            .authority = "localhost",
            .path = "/routed",
            .origin = "https://localhost",
            .limits = .{ .http3 = limits, .max_session_streams = 8 },
            .h3 = .{ .local_settings = settings },
        },
    );
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();

    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .reliable_reset = .{ .local = true, .peer = true },
        .enable_pacing = false,
    });
    defer server.deinit();
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .headers = &.{http3.capsule.protocol_header},
        .extended_connect = true,
    }).write(&response_bytes, allocator);
    var server_control = http3.ControlState{};
    var settings_bytes: std.ArrayList(u8) = .empty;
    defer settings_bytes.deinit(allocator);
    try server_control.writeSettingsStream(
        &settings_bytes,
        allocator,
        settings,
    );
    try startPendingMockRequest(&server, &pending, settings_bytes.items);
    const response_frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = pending.sessionId().value,
            .data = response_bytes.items,
        } },
    };
    try server.send(&response_frames);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, pending.connection());
    try std.testing.expect((try pending.pollConnect()) == null);
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var completed: ?runtime.HandshakeConnectAttempt = null;
    while (completed == null) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try pending.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
                if (try pending.pollConnectForDispatcher(
                    &dispatcher,
                    1,
                )) |attempt_value| {
                    pending_owned = false;
                    completed = attempt_value;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    var attempt = completed.?;
    var session: runtime.HandshakeClientSession = undefined;
    try attempt.requireAcceptedForDispatcher(
        &dispatcher,
        1,
        &session,
    );
    defer session.deinit();
    const session_id = session.session_id.value;

    var stream_header: std.ArrayList(u8) = .empty;
    defer stream_header.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &stream_header,
        allocator,
        session.session_id,
    );
    var control_storage: [16]u8 = undefined;
    const drain = try session_control.writeDrainInto(&control_storage);
    var framed_control: [32]u8 = undefined;
    const framed_control_len = try writeDataFrame(&framed_control, drain);
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 7,
            .data = stream_header.items,
        } },
        .{ .stream = .{
            .stream_id = 7,
            .offset = stream_header.items.len,
            .data = "incremental",
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 19,
            .data = stream_header.items,
        } },
        .{ .stream = .{
            .stream_id = 19,
            .offset = stream_header.items.len,
            .data = "complete",
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = session_id,
            .offset = response_bytes.items.len,
            .data = framed_control[0..framed_control_len],
        } },
    };
    try server.send(&frames);
    try sendDatagram(
        &server,
        session.session_id,
        "client-datagram",
    );

    try std.testing.expect((try session.pollCompleteStream()) == null);
    try std.testing.expect((try session.pollDatagram()) == null);
    try std.testing.expect((try session.pollSessionEvent()) == null);

    var saw_incremental_stream = false;
    var saw_complete_stream = false;
    var saw_datagram = false;
    var saw_drain = false;
    var stream_buffer: [32]u8 = undefined;
    while (!saw_incremental_stream or !saw_complete_stream or
        !saw_datagram or !saw_drain)
    {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try std.testing.expectEqual(
                    @as(usize, 1),
                    routed.connection_handle,
                );
                try session.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);

                if (try session.pollStream(&stream_buffer)) |stream| {
                    if (stream != .data) return error.TestUnexpectedResult;
                    try std.testing.expectEqual(@as(u62, 7), stream.data.stream_id);
                    try std.testing.expect(stream.data.fin);
                    try std.testing.expectEqualStrings(
                        "incremental",
                        stream_buffer[0..stream.data.bytes],
                    );
                    saw_incremental_stream = true;
                }
                if (try session.pollCompleteStream()) |stream_value| {
                    var stream = stream_value;
                    defer stream.deinit();
                    try std.testing.expectEqual(@as(u62, 19), stream.stream_id);
                    try std.testing.expectEqual(
                        webtransport.StreamDirection.unidirectional,
                        stream.direction,
                    );
                    try std.testing.expect(!stream.locally_initiated);
                    try std.testing.expect(stream.fin);
                    try std.testing.expectEqualStrings(
                        "complete",
                        stream.payload,
                    );
                    saw_complete_stream = true;
                }
                if (try session.pollDatagram()) |datagram_value| {
                    var datagram = datagram_value;
                    defer datagram.deinit(allocator);
                    try std.testing.expectEqualStrings(
                        "client-datagram",
                        datagram.datagram.payload,
                    );
                    saw_datagram = true;
                }
                if (try session.pollSessionEvent()) |control| {
                    try std.testing.expect(control == .draining);
                    saw_drain = true;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
}

test "WebTransport client CONNECT polling defers paced feedback and credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = "wt-paced-client";
    const server_cid = "wt-paced-server";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 512;
    client_transport.initial_max_stream_data_bidi_local = 512;
    client_transport.max_datagram_frame_size = 1200;

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
    var pending = try runtime.HandshakeClientSession.beginEstablishedConnect(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = client_transport,
                .peer_transport_parameters = quic.practical_transport_parameters,
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                    .receive_window = 512,
                    .stream_receive_window = 512,
                },
            },
        ),
        .{
            .authority = "localhost",
            .path = "/paced-client",
            .origin = "https://localhost",
            .limits = .{ .max_session_streams = 8 },
            .h3 = .{ .local_settings = settings },
        },
    );
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();

    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .reliable_reset = .{ .local = true, .peer = true },
        .enable_pacing = false,
    });
    defer server.deinit();

    var padding: [320]u8 = undefined;
    for (&padding, 0..) |*byte, index| {
        byte.* = @intCast('!' + index % ('~' - '!' + 1));
    }
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .headers = &.{
            http3.capsule.protocol_header,
            .{ .name = "x-padding", .value = &padding },
        },
        .extended_connect = true,
    }).write(&response_bytes, allocator);
    try std.testing.expect(response_bytes.items.len > 256);
    try std.testing.expect(response_bytes.items.len <= 512);

    var server_control = http3.ControlState{};
    var settings_bytes: std.ArrayList(u8) = .empty;
    defer settings_bytes.deinit(allocator);
    try server_control.writeSettingsStream(
        &settings_bytes,
        allocator,
        settings,
    );
    try startPendingMockRequest(&server, &pending, settings_bytes.items);
    try server.send(&.{
        .{ .stream = .{
            .stream_id = pending.sessionId().value,
            .data = response_bytes.items,
        } },
    });
    var response_packet = try pending.connection().receivePacket();
    defer response_packet.deinit(allocator);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 23;
    try dispatcher.registerConnection(handle, pending.connection());

    for (0..1400) |_| {
        try pending.h3.?.qpack_decode.recordStreamCancellation(0);
    }
    const feedback_len =
        pending.h3.?.qpack_decode.pendingDecoderInstructions().len;
    const decoder_offset = pending.h3.?.qpack_decoder_send.next_offset;

    var fixed_io = FixedClockIo{
        .delegate = client_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = client_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    client_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer client_endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        pending.connection(),
        @intCast(fixed_io.now_ns),
    );

    try pending.processPacket(&response_packet);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        feedback_len,
        pending.h3.?.qpack_decode.pendingDecoderInstructions().len,
    );
    try std.testing.expectEqual(
        decoder_offset,
        pending.h3.?.qpack_decoder_send.next_offset,
    );
    const response_available = quic.one_rtt.testing
        .receiveStreamAvailableLen(
        pending.connection(),
        pending.sessionId().value,
    ).?;
    try std.testing.expectEqual(response_bytes.items.len, response_available);

    const packet_number = pending.connection().next_packet_number;
    try std.testing.expect((try pending.pollConnectForDispatcher(
        &dispatcher,
        handle,
    )) == null);
    try std.testing.expect(pending.h3.?.dispatcherBound());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(packet_number, pending.connection().next_packet_number);
    try std.testing.expectEqual(
        response_available,
        quic.one_rtt.testing.receiveStreamAvailableLen(
            pending.connection(),
            pending.sessionId().value,
        ).?,
    );

    var saw_feedback_progress = false;
    var saw_credit_deferral = false;
    var completed: ?runtime.HandshakeConnectAttempt = null;
    for (0..8) |_| {
        const timer = dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            quic.one_rtt.TimerDeadlineKind.pacing,
            timer.timer.kind,
        );
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
            return error.TestUnexpectedResult;
        const before =
            pending.h3.?.qpack_decode.pendingDecoderInstructions().len;
        if (try pending.pollConnectForDispatcher(
            &dispatcher,
            handle,
        )) |attempt| {
            pending_owned = false;
            completed = attempt;
            break;
        }
        const after =
            pending.h3.?.qpack_decode.pendingDecoderInstructions().len;
        saw_feedback_progress = saw_feedback_progress or after < before;
        saw_credit_deferral = saw_credit_deferral or after == 0;
        try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
        try std.testing.expectEqual(
            response_available,
            quic.one_rtt.testing.receiveStreamAvailableLen(
                pending.connection(),
                pending.sessionId().value,
            ).?,
        );
        try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    }
    try std.testing.expect(saw_feedback_progress);
    try std.testing.expect(saw_credit_deferral);

    var attempt = completed orelse return error.TestUnexpectedResult;
    try std.testing.expect(
        attempt.h3.?.qpack_decoder_send.next_offset > decoder_offset,
    );
    var session: runtime.HandshakeClientSession = undefined;
    const peer_settings = attempt.h3.?.control.settings.peer;
    attempt.h3.?.control.settings.peer.h3_datagram = false;
    try std.testing.expectError(
        error.DatagramsNotNegotiated,
        attempt.requireAcceptedForDispatcher(
            &dispatcher,
            handle,
            &session,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectError(
        error.InvalidDispatcherState,
        attempt.requireAccepted(),
    );
    attempt.h3.?.control.settings.peer = peer_settings;
    try attempt.requireAcceptedForDispatcher(
        &dispatcher,
        handle,
        &session,
    );
    var session_owned = true;
    defer if (session_owned) session.deinit();
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(@as(u16, 200), session.response.status);
    session.deinit();
    session_owned = false;
    try std.testing.expectEqual(@as(usize, 0), dispatcher.connectionCount());
}

test "WebTransport dispatcher CONNECT attempt deinit never waits for pacing" {
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
        [_]u8{0xaf} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var h3 = try http3.runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "wt-attempt-client",
                .peer_connection_id = "wt-attempt-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{ .local_settings = settings },
    );
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    const stream_id = try h3.startRequest(.{
        .method = "CONNECT",
        .path = "/abandon",
        .authority = "localhost",
        .headers = &.{.{
            .name = ":protocol",
            .value = "webtransport",
        }},
    }, null);
    try h3.bindDispatcher();

    const empty_headers = try allocator.alloc(http3.Qpack.HeaderField, 0);
    const empty_body = try allocator.alloc(u8, 0);
    const empty_trailers = try allocator.alloc(http3.Qpack.HeaderField, 0);
    var restored: http3.runtime.HandshakeClient = undefined;
    var attempt = runtime.HandshakeConnectAttempt{
        .h3 = h3,
        .restore_to = &restored,
        .session_id = .init(stream_id),
        .response = .{
            .status = 200,
            .headers = empty_headers,
            .content_length = null,
            .body_allowed = true,
            .consumed = 0,
            .qpack_section_acknowledgments = 0,
        },
        .response_body = empty_body,
        .response_trailers = empty_trailers,
        .limits = .{},
    };
    var restored_owned = false;
    defer if (restored_owned) restored.deinit();

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 41;
    try dispatcher.registerConnection(
        handle,
        &attempt.h3.?.established.connection,
    );
    attempt.dispatcher_registered = true;
    attempt.dispatcher = &dispatcher;
    attempt.dispatcher_handle = handle;

    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 6_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    endpoint.io = .{ .userdata = &fixed_io, .vtable = &fixed_vtable };
    defer endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &attempt.h3.?.established.connection,
        @intCast(fixed_io.now_ns),
    );

    attempt.deinit();
    restored_owned = true;
    try std.testing.expectEqual(@as(usize, 0), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        http3.runtime.testing.clientRequestCount(&restored),
    );
    try std.testing.expect(!restored.isReusable());
}

test "WebTransport dispatcher client stream polls do not wait for credit" {
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
        [_]u8{0xe7} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var local_parameters = quic.practical_transport_parameters;
    local_parameters.initial_max_data = 128;
    local_parameters.initial_max_stream_data_uni = 64;
    var h3 = try http3.runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "wt-poll-client",
                .peer_connection_id = "wt-poll-server",
                .local_transport_parameters = local_parameters,
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                    .receive_window = 64,
                    .stream_receive_window = 64,
                },
            },
        ),
        .{ .local_settings = settings },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .client,
        settings,
        settings,
        8,
        4,
        14,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();

    var response = http3.DecodedResponseHead{
        .status = 200,
        .headers = &.{},
        .content_length = null,
        .consumed = 0,
        .body_allowed = true,
        .qpack_section_acknowledgments = 0,
    };
    var response_owned = true;
    defer if (response_owned) response.deinit(allocator);
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 25;
    try dispatcher.registerConnection(handle, &h3.established.connection);
    var session = runtime.HandshakeClientSession{
        .h3 = h3,
        .session_id = .init(0),
        .response = response,
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
        .dispatcher = &dispatcher,
        .dispatcher_handle = handle,
    };
    h3_owned = false;
    streams_owned = false;
    response_owned = false;
    defer session.deinit();
    defer _ = dispatcher.unregisterConnection(handle) catch false;
    try dispatcher.replaceConnection(
        handle,
        &session.h3.established.connection,
    );

    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 3_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer endpoint.io = fixed_io.delegate;

    var incremental_bytes: std.ArrayList(u8) = .empty;
    defer incremental_bytes.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &incremental_bytes,
        allocator,
        session.session_id,
    );
    try incremental_bytes.appendSlice(allocator, &([_]u8{'i'} ** 40));
    try quic.one_rtt.testing.applyReceivedFrames(
        &session.h3.established.connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 3,
            .data = incremental_bytes.items,
        } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    quic.one_rtt.testing.exhaustPacingAt(
        &session.h3.established.connection,
        @intCast(fixed_io.now_ns),
    );
    const packet_number = session.h3.established.connection.next_packet_number;
    var buffer: [64]u8 = undefined;
    const incremental = (try session.pollStream(&buffer)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(incremental == .data);
    try std.testing.expectEqual(@as(u62, 3), incremental.data.stream_id);
    try std.testing.expectEqualStrings(&([_]u8{'i'} ** 40), buffer[0..incremental.data.bytes]);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(packet_number, session.h3.established.connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 40), session.streams.get(3).?.bytes_received);
    try std.testing.expectEqual(@as(usize, 0), quic.one_rtt.testing.receiveStreamAvailableLen(&session.h3.established.connection, 3).?);
    try std.testing.expect(session.h3.established.connection.receive_credit_retry_deadline_ns != null);
    for (0..16) |_| {
        if (session.h3.established.connection.receive_credit_retry_deadline_ns == null) break;
        const timer = dispatcher.nextTimerDeadline().?;
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse return error.TestUnexpectedResult;
    }
    try std.testing.expect(session.h3.established.connection.receive_credit_retry_deadline_ns == null);
    try std.testing.expect((try session.pollStream(&buffer)) == null);

    var whole_bytes: std.ArrayList(u8) = .empty;
    defer whole_bytes.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &whole_bytes,
        allocator,
        session.session_id,
    );
    try whole_bytes.appendSlice(allocator, &([_]u8{'w'} ** 40));
    try quic.one_rtt.testing.applyReceivedFrames(
        &session.h3.established.connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 7,
            .data = whole_bytes.items,
            .fin = true,
        } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    quic.one_rtt.testing.exhaustPacingAt(
        &session.h3.established.connection,
        @intCast(fixed_io.now_ns),
    );
    var whole = (try session.pollCompleteStream()) orelse return error.TestUnexpectedResult;
    defer whole.deinit();
    try std.testing.expectEqual(@as(u62, 7), whole.stream_id);
    try std.testing.expectEqualStrings(&([_]u8{'w'} ** 40), whole.payload);
    try std.testing.expectEqual(@as(u64, 40), session.streams.get(7).?.bytes_received);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(session.h3.established.connection.receive_credit_retry_deadline_ns != null);
    for (0..16) |_| {
        if (session.h3.established.connection.receive_credit_retry_deadline_ns == null) break;
        const timer = dispatcher.nextTimerDeadline().?;
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse return error.TestUnexpectedResult;
    }
    try std.testing.expect(session.h3.established.connection.receive_credit_retry_deadline_ns == null);
    try std.testing.expect((try session.pollCompleteStream()) == null);

    try std.testing.expectError(
        error.InvalidDispatcherState,
        session.receiveDatagramWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.InvalidDispatcherState,
        session.receiveStreamWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.InvalidDispatcherState,
        session.readStreamWithTimeout(&buffer, .fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.InvalidDispatcherState,
        session.receiveSessionEventWithTimeout(.fromMilliseconds(1)),
    );
    const bounded_stream = (try session.streams.openLocal(.bidirectional))
        .stream_id;
    const bounded_writes = [_]runtime.StreamWrite{.{
        .stream_id = bounded_stream,
        .data = "bounded",
    }};
    var bounded_counts = [_]usize{99};
    const sends_before_bounded_batch = fixed_io.send_calls;
    try std.testing.expectError(
        error.InvalidDispatcherState,
        session.resetStreamWithDeadline(
            bounded_stream,
            42,
            .fromNow(endpoint.io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(sends_before_bounded_batch, fixed_io.send_calls);
    try std.testing.expectError(
        error.InvalidDispatcherState,
        session.writeStreamsWithDeadline(
            &bounded_writes,
            &bounded_counts,
            .fromNow(endpoint.io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), bounded_counts[0]);
    try std.testing.expectEqual(sends_before_bounded_batch, fixed_io.send_calls);
    const bounded_state = session.streams.get(bounded_stream) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!bounded_state.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), bounded_state.send_offset);
    try std.testing.expectEqual(@as(u64, 0), bounded_state.bytes_sent);
    try std.testing.expectEqual(
        @as(?webtransport.StreamError, null),
        bounded_state.send_reset,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
}

test "WebTransport client polls complete rejected CONNECT entity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = "wt-reject-client";
    const server_cid = "wt-reject-server";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
    const limits = http3.runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer client_endpoint.deinit();
    var pending = try runtime.HandshakeClientSession.beginEstablishedConnect(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = transport_parameters,
                .peer_transport_parameters = transport_parameters,
                .one_rtt = .{ .enable_pacing = false },
            },
        ),
        .{
            .authority = "localhost",
            .path = "/rejected",
            .origin = "https://localhost",
            .limits = .{ .http3 = limits, .max_session_streams = 8 },
            .h3 = .{ .local_settings = settings },
        },
    );
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();

    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .reliable_reset = .{ .local = true, .peer = true },
        .enable_pacing = false,
    });
    defer server.deinit();
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{
        .status = 429,
        .headers = &.{.{ .name = "retry-after", .value = "5" }},
        .body = "slow down",
        .trailers = &.{.{ .name = "x-final", .value = "true" }},
        .request_method = "CONNECT",
        .extended_connect = true,
    }).write(&response_bytes, allocator);
    var server_control = http3.ControlState{};
    var settings_bytes: std.ArrayList(u8) = .empty;
    defer settings_bytes.deinit(allocator);
    try server_control.writeSettingsStream(
        &settings_bytes,
        allocator,
        settings,
    );
    try startPendingMockRequest(&server, &pending, settings_bytes.items);
    const response_frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = pending.sessionId().value,
            .data = response_bytes.items,
            .fin = true,
        } },
    };
    try server.send(&response_frames);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, pending.connection());
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var completed: ?runtime.HandshakeConnectAttempt = null;
    while (completed == null) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try pending.processPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
                if (try pending.pollConnectForDispatcher(
                    &dispatcher,
                    1,
                )) |attempt| {
                    pending_owned = false;
                    completed = attempt;
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    var attempt = completed.?;
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 429), attempt.status());
    try std.testing.expectEqualStrings(
        "5",
        attempt.responseHeader("retry-after").?,
    );
    try std.testing.expectEqualStrings("slow down", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "true",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );
}

test "WebTransport client rejection body is not repeated by paced credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = "wt-reject-client-p";
    const server_cid = "wt-reject-server-p";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd6} ** quic.protection.secret_len,
    );
    const settings = webtransport.defaultSettings(.{});
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 1024;
    client_transport.initial_max_stream_data_bidi_local = 1024;
    client_transport.max_datagram_frame_size = 1200;

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
    var pending = try runtime.HandshakeClientSession.beginEstablishedConnect(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = client_transport,
                .peer_transport_parameters = quic.practical_transport_parameters,
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                    .receive_window = 1024,
                    .stream_receive_window = 1024,
                },
            },
        ),
        .{
            .authority = "localhost",
            .path = "/paced-rejection",
            .origin = "https://localhost",
            .limits = .{ .max_rejection_body_bytes = 1024 },
            .h3 = .{ .local_settings = settings },
        },
    );
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();

    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .reliable_reset = .{ .local = true, .peer = true },
        .enable_pacing = false,
    });
    defer server.deinit();

    const body = [_]u8{'r'} ** 600;
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{
        .status = 429,
        .body = &body,
        .trailers = &.{.{ .name = "x-final", .value = "true" }},
        .request_method = "CONNECT",
        .extended_connect = true,
    }).write(&response_bytes, allocator);
    try std.testing.expect(response_bytes.items.len < 1024);
    var server_control = http3.ControlState{};
    var settings_bytes: std.ArrayList(u8) = .empty;
    defer settings_bytes.deinit(allocator);
    try server_control.writeSettingsStream(
        &settings_bytes,
        allocator,
        settings,
    );
    try startPendingMockRequest(&server, &pending, settings_bytes.items);
    try server.send(&.{
        .{ .stream = .{
            .stream_id = pending.sessionId().value,
            .data = response_bytes.items,
            .fin = true,
        } },
    });
    var response_packet = try pending.connection().receivePacket();
    defer response_packet.deinit(allocator);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 24;
    try dispatcher.registerConnection(handle, pending.connection());

    var fixed_io = FixedClockIo{
        .delegate = client_endpoint.io,
        .now_ns = 2_000_000,
    };
    var fixed_vtable = client_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    fixed_vtable.netSend = FixedClockIo.netSend;
    client_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer client_endpoint.io = fixed_io.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        pending.connection(),
        @intCast(fixed_io.now_ns),
    );

    try pending.processPacket(&response_packet);
    try std.testing.expect((try pending.pollConnectForDispatcher(
        &dispatcher,
        handle,
    )) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(body.len, pending.rejection_body.items.len);
    try std.testing.expectEqualStrings(&body, pending.rejection_body.items);
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    const packet_number = pending.connection().next_packet_number;

    // The body was delivered before its receive-credit update hit pacing. A
    // second poll at the same clock must neither wait nor append it again.
    try std.testing.expect((try pending.pollConnectForDispatcher(
        &dispatcher,
        handle,
    )) == null);
    try std.testing.expectEqual(body.len, pending.rejection_body.items.len);
    try std.testing.expectEqualStrings(&body, pending.rejection_body.items);
    try std.testing.expectEqual(
        packet_number,
        pending.connection().next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);

    var completed: ?runtime.HandshakeConnectAttempt = null;
    for (0..4) |_| {
        const timer = dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            quic.one_rtt.TimerDeadlineKind.pacing,
            timer.timer.kind,
        );
        fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
        _ = (try dispatcher.serviceNextTimerAt(timer.timer.deadline_ns)) orelse
            return error.TestUnexpectedResult;
        if (try pending.pollConnectForDispatcher(
            &dispatcher,
            handle,
        )) |attempt| {
            pending_owned = false;
            completed = attempt;
            break;
        }
        try std.testing.expectEqual(body.len, pending.rejection_body.items.len);
        try std.testing.expectEqualStrings(&body, pending.rejection_body.items);
        try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    }
    var attempt = completed orelse return error.TestUnexpectedResult;
    pending_owned = false;
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 429), attempt.status());
    try std.testing.expectEqualStrings(&body, attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "true",
        attempt.trailers()[0].value,
    );
    try std.testing.expectEqual(@as(usize, 0), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
}

test "WebTransport handshake admission polls routed CONNECT state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});
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
    const peer = client_endpoint.address();
    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer,
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-server",
            .peer_connection_id = "wt-client",
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
        },
    );
    var admission = runtime.HandshakeAdmission{
        .h3 = h3,
        .limits = .{ .max_session_streams = 8 },
    };
    h3 = undefined;
    var admission_owned = true;
    defer if (admission_owned) admission.deinit();
    try admission.h3.ensureSettingsSent();
    try admission.h3.bindDispatcher();
    admission.h3.control.settings.markReceived(settings);
    try std.testing.expect((try admission.pollSessionRequest()) == null);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/routed",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport-h3" },
            http3.capsule.protocol_header,
        },
    }).write(&encoded, allocator);
    var client = try quic.one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-client",
        .peer_connection_id = "wt-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items,
        .fin = false,
    } }};
    try client.send(&frames);
    var packet = try admission.h3.established.connection.receivePacket();
    defer packet.deinit(allocator);
    try admission.processPacket(&packet);

    var pending = (try admission.pollSessionRequest()) orelse
        return error.TestUnexpectedResult;
    admission_owned = false;
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    try std.testing.expectEqualStrings("localhost", pending.authority().?);
    try std.testing.expectEqualStrings("/routed", pending.path());
    var accepted = try pending.accept();
    pending_owned = false;
    defer accepted.deinit();
    try std.testing.expectError(
        error.InvalidDispatcherState,
        accepted.closeWithDeadline(1, "routed", .fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        )),
    );
}

test "WebTransport routed Initial timeout preserves event ownership" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "wt-routed-deadline" } },
    );
    defer server.deinit();

    const bytes = try allocator.dupe(u8, "owned-initial");
    var event = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(4567) },
            .bytes = bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = bytes[0..8],
        .source_connection_id = bytes[8..],
        .first_packet_len = bytes.len,
    } };
    defer event.deinit(allocator);

    try std.testing.expectError(
        error.Timeout,
        server.receiveSessionRequestFromInitialWithTimeout(
            &event,
            .zero,
        ),
    );
    try std.testing.expect(event == .new_initial);
    try std.testing.expectError(
        error.Timeout,
        server.beginSessionAdmissionFromInitialSourceWithTimeout(
            .fromEndpoint(&server.h3.quic_server.endpoint),
            &event,
            .zero,
        ),
    );
    try std.testing.expect(event == .new_initial);
}

test "WebTransport routed admission keeps its handshake deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xef} ** quic.protection.secret_len,
    );
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

    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_endpoint.address(),
        .{ .local_settings = webtransport.defaultSettings(.{}) },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-server",
            .peer_connection_id = "wt-client",
        },
    );
    var admission = runtime.HandshakeAdmission{
        .h3 = h3,
        .limits = .{},
        .deadline = .fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        ),
    };
    h3 = undefined;
    defer admission.deinit();
    try std.Io.sleep(io, .fromMilliseconds(5), .awake);

    try std.testing.expectError(
        error.Timeout,
        admission.pollSessionRequest(),
    );
}

test "WebTransport handshake receive helpers honor timeouts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});

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

    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "wt-timeout-server",
            .peer_connection_id = "wt-timeout-client",
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var session = runtime.AcceptedHandshakeSession{
        .h3 = h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(std.testing.allocator, .init(0)),
    };
    h3_owned = false;
    streams_owned = false;
    defer {
        session.control.deinit();
        session.streams.deinit();
        session.h3.deinit();
    }
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-timeout-client",
        .peer_connection_id = "wt-timeout-server",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer peer.deinit();

    try std.testing.expectError(
        error.Timeout,
        session.receiveDatagramWithTimeout(.fromMilliseconds(1)),
    );
    var buffer: [32]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        session.readStreamWithTimeout(&buffer, .fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveSessionEventWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveDatagramWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.readStreamWithDeadline(
            &buffer,
            .fromNow(
                io,
                .{ .raw = .fromMilliseconds(1), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveSessionEventWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receivePeerConnectionCloseWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveStreamWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receiveStreamWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(1), .clock = .awake },
        )),
    );
    try std.testing.expectError(
        error.Timeout,
        session.receivePeerConnectionCloseWithTimeout(
            .fromMilliseconds(1),
        ),
    );

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        .init(0),
    );
    const first_payload = "partial-";
    const partial_frames = [_]quic.Frame{ .{ .stream = .{
        .stream_id = 4,
        .data = prefix,
    } }, .{ .stream = .{
        .stream_id = 4,
        .offset = prefix.len,
        .data = first_payload,
    } } };
    try peer.send(&partial_frames);
    var partial_packet =
        try session.h3.established.connection.receivePacket();
    defer partial_packet.deinit(allocator);
    try session.processPacket(&partial_packet);
    try std.testing.expectError(
        error.Timeout,
        session.receiveStreamWithTimeout(.fromMilliseconds(1)),
    );

    // A bounded whole-stream receive must leave QUIC reassembly and the
    // WebTransport association intact when FIN has not arrived yet.
    const final_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = prefix.len + first_payload.len,
        .data = "complete",
        .fin = true,
    } }};
    try peer.send(&final_frames);
    var received = try session.receiveStreamWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer received.deinit();
    try std.testing.expectEqual(@as(u62, 4), received.stream_id);
    try std.testing.expectEqual(
        webtransport.StreamDirection.bidirectional,
        received.direction,
    );
    try std.testing.expect(!received.locally_initiated);
    try std.testing.expect(received.fin);
    try std.testing.expectEqualStrings(
        "partial-complete",
        received.payload,
    );
}

fn writeDataFrame(out: []u8, payload: []const u8) !usize {
    const frame_type = try quic.varint.encodeInto(
        out,
        http3.FrameType.data,
    );
    const length = try quic.varint.encodeInto(
        out[frame_type.len..],
        payload.len,
    );
    const start = frame_type.len + length.len;
    if (payload.len > out.len - start) return error.BufferTooShort;
    @memcpy(out[start..][0..payload.len], payload);
    return start + payload.len;
}

fn sendDatagram(
    connection: *quic.one_rtt.Connection,
    session_id: webtransport.SessionId,
    payload: []const u8,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try (webtransport.Datagram{
        .session_id = session_id,
        .payload = payload,
    }).write(&encoded, std.testing.allocator);
    try connection.sendDatagram(encoded.items);
}

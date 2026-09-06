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
        .control = try session_control.Control.init(.init(0)),
    };
    // Ownership moved to `accepted`; avoid the outer defer.
    streams_owned = false;
    defer accepted.streams.deinit();

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
    var failed_vtable = server_endpoint.io.vtable.*;
    failed_vtable.netSend = ObservedBatchSend.netSend;
    server_endpoint.io = .{
        .userdata = &failed_send,
        .vtable = &failed_vtable,
    };
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
        .control = try session_control.Control.init(.init(0)),
    };
    streams_owned = false;
    defer accepted.streams.deinit();

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
    const connection_timer = h3.established.connection
        .nextTimerDeadline() orelse return error.TestUnexpectedResult;
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
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
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
        .control = try session_control.Control.init(.init(0)),
    };
    streams_owned = false;
    defer accepted.streams.deinit();
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
        .control = try session_control.Control.init(.init(0)),
    };
    streams_owned = false;
    defer accepted.streams.deinit();
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
        try accepted.writeStream(stream_id, "x"),
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
        .control = try session_control.Control.init(.init(0)),
    };
    streams_owned = false;
    defer accepted.streams.deinit();
    const reset_stream_id = try accepted.openBidirectionalStream();
    const stopped_stream_id: u62 = 0;
    const stopped_stream = try accepted.streams.registerPeer(
        stopped_stream_id,
        .bidirectional,
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
        .{ .stream = .{ .stream_id = stopped_stream_id, .data = &.{} } },
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
    try std.testing.expect(stopped_stream.stop_sent == null);
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
    try std.testing.expect(stopped_stream.stop_sent != null);

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
    defer session.deinit();
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
    try std.testing.expect(try dispatcher.unregisterConnection(1));
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
        .control = try session_control.Control.init(.init(0)),
    };
    server_a_h3_owned = false;
    streams_a_owned = false;
    defer {
        session_a.streams.deinit();
        session_a.h3.deinit();
    }
    var session_b = runtime.AcceptedHandshakeSession{
        .h3 = server_b_h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams_b,
        .control = try session_control.Control.init(.init(0)),
    };
    server_b_h3_owned = false;
    streams_b_owned = false;
    defer {
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
    const response_frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 3,
            .data = settings_bytes.items,
        } },
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
    const response_frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 3, .data = settings_bytes.items } },
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
    admission.h3.control.settings.markSent(settings);
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
            .{ .name = ":protocol", .value = "webtransport" },
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
    defer pending.deinit();
    try std.testing.expectEqualStrings("localhost", pending.authority().?);
    try std.testing.expectEqualStrings("/routed", pending.path());
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
        .control = try session_control.Control.init(.init(0)),
    };
    h3_owned = false;
    streams_owned = false;
    defer {
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

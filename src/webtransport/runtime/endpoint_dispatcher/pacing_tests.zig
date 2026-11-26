const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const webtransport = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const handshake_stream = @import("../stream.zig");
const session_control = @import("../session_control.zig");
const FixedClockIo = @import("../../../internal/testing/deadline_send_io.zig").Native;
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");

test "WebTransport endpoint control and datagram sends do not wait for pacing" {
    try native_protocol_io.run(controlAndDatagramPacing);
}

fn controlAndDatagramPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

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
    // without a pacing duration sleep. Absolute deadline watchers use
    // actual cancellable waits and are joined before the operation returns.
    var fixed_io = FixedClockIo{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = server_endpoint.io,
        .now_ns = .init(1_000_000),
    };
    defer fixed_io.backend.deinit();
    server_endpoint.io = fixed_io.io();
    defer server_endpoint.io = fixed_io.baseIo();

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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), fixed_io.send_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(reset_timer.timer.deadline_ns));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(stop_timer.timer.deadline_ns));
    const stop_timer_event = (try dispatcher.serviceNextTimerAt(
        stop_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        stop_timer_event.timer.kind,
    );
    try accepted.stopStream(stopped_stream_id, 42);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 3), fixed_io.send_calls.load(.acquire));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(datagram_timer.timer.deadline_ns));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(bounded_timer.timer.deadline_ns));
    _ = (try dispatcher.serviceNextTimerAt(
        bounded_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.trySendDatagramWithDeadline(
        "bounded-attempt",
        bounded_deadline,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(datagram_batch_timer.timer.deadline_ns));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(
        before_datagram.datagrams_sent + 4,
        accepted.stats().datagrams_sent,
    );

    const body_offset = h3.outbound_bodies.find(0).?.send.next_offset;
    try std.testing.expectError(
        error.PacingLimited,
        accepted.sendSessionData("not-sent", false),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(body_timer.timer.deadline_ns));
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
                fixed_io.setNow(@intCast(retry_timer.timer.deadline_ns));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expect(
        h3.outbound_bodies.find(0).?.send.next_offset > body_offset,
    );

    const before_drain_offset = h3.outbound_bodies.find(0).?.send.next_offset;
    try std.testing.expectError(error.PacingLimited, accepted.drain());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(drain_timer.timer.deadline_ns));
    _ = (try dispatcher.serviceNextTimerAt(
        drain_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.drain();
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
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
    fixed_io.setNow(@intCast(close_timer.timer.deadline_ns));
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
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(
        cleanup_packet_number,
        h3.established.connection.next_packet_number,
    );
    try std.testing.expect(
        accepted.streams.get(close_send_id).?.send_reset == null,
    );
    const reset_close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(reset_close_timer.timer.deadline_ns));
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
    fixed_io.setNow(@intCast(stop_close_timer.timer.deadline_ns));
    _ = (try dispatcher.serviceNextTimerAt(
        stop_close_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try accepted.close(71, "ignored after capsule commit");
    try std.testing.expect(close_receive.stop_sent != null);
    const send_calls_after_cleanup = fixed_io.send_calls.load(.acquire);
    try accepted.close(71, "ignored after capsule commit");
    try std.testing.expectEqual(
        send_calls_after_cleanup,
        fixed_io.send_calls.load(.acquire),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

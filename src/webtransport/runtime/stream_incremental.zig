//! Incremental caller-buffer WebTransport stream reads and cancellation.

const std = @import("std");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const association = @import("stream_association.zig");

pub const Error = association.Error;
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

pub const Read = union(enum) {
    data: struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        locally_initiated: bool,
        bytes: usize,
        /// True when these are the final application bytes, or when FIN was
        /// already consumed and this is the stream's zero-byte EOF event.
        fin: bool,
    },
    reset: struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        locally_initiated: bool,
        error_info: webtransport.StreamError,
        final_size: u64,
    },
    stopped: struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        locally_initiated: bool,
        error_info: webtransport.StreamError,
    },
};

/// Read the next stream event into caller storage without waiting for FIN.
///
/// Each returned data prefix is immediately released to QUIC flow control, so
/// a long-lived stream can exceed its receive window without whole-body
/// retention. With UDP_GRO enabled, one kernel batch is applied before polling
/// again, but the call still returns one fairly selected stream event and does
/// not wait for future datagrams to fill `out`. The buffer must be non-empty.
pub fn read(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!Read {
    if (out.len == 0) return error.BufferTooShort;
    while (true) {
        if (try poll(connection, registry, session_id, out)) |event| {
            return event;
        }

        // `poll` reads assembled QUIC stream state, so packet plaintext and
        // frame arrays do not need ownership beyond transport processing.
        try serviceReceive(connection);
    }
}

/// Deadline-bounded counterpart to `read`. One absolute deadline spans all
/// unrelated/control packets and any earlier QUIC transport timers.
pub fn readWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!Read {
    if (out.len == 0) return error.BufferTooShort;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    while (true) {
        if (try poll(connection, registry, session_id, out)) |event| {
            return event;
        }
        try serviceReceiveWithDeadline(connection, deadline);
    }
}

/// Read the next event for one associated stream without consuming ready data
/// from sibling streams. This is useful for long-lived control streams that
/// share a WebTransport session with independently scheduled application data.
pub fn readId(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
) Error!Read {
    if (out.len == 0) return error.BufferTooShort;
    while (true) {
        _ = try association.drainAbandonedReceives(
            connection,
            registry,
            false,
        );
        var transport_progressed = false;
        if (try pollStream(
            connection,
            registry,
            session_id,
            stream_id,
            out,
            false,
            &transport_progressed,
        )) |event| return event;
        try serviceReceive(connection);
    }
}

/// Deadline-bounded targeted stream read. One absolute deadline spans sibling
/// packets and all earlier QUIC transport timers.
pub fn readIdWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!Read {
    if (out.len == 0) return error.BufferTooShort;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    while (true) {
        _ = try association.drainAbandonedReceives(
            connection,
            registry,
            false,
        );
        var transport_progressed = false;
        if (try pollStream(
            connection,
            registry,
            session_id,
            stream_id,
            out,
            false,
            &transport_progressed,
        )) |event| return event;
        try serviceReceiveWithDeadline(connection, deadline);
    }
}

fn serviceReceive(connection: *quic.one_rtt.Connection) Error!void {
    if (!connection.endpoint.groReceiveEnabled()) {
        return connection.servicePacketServicingTimers();
    }
    _ = try connection.servicePacketBatchServicingTimers();
}

fn serviceReceiveWithDeadline(
    connection: *quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!void {
    if (!connection.endpoint.groReceiveEnabled()) {
        return connection.servicePacketServicingTimersDeadline(deadline);
    }
    _ = try connection.servicePacketBatchServicingTimersDeadline(
        deadline,
    );
}

test "WebTransport incremental poll rejects wrong-session bidi before sibling" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8d} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-wrong-bidi-server",
        .peer_connection_id = "wt-wrong-bidi-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 32,
        .receive_window = 32,
        .max_receive_window = 32,
        .initial_receive_max_stream_data = 12,
        .stream_receive_window = 12,
        .max_stream_receive_window = 12,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var wrong_header_storage: [16]u8 = undefined;
    const wrong_header = try webtransport.BidirectionalStreamHeader.writeInto(
        &wrong_header_storage,
        .init(4),
    );
    var wrong_bytes_storage: [32]u8 = undefined;
    const wrong_bytes = wrong_bytes_storage[0 .. wrong_header.len + "wrong!".len];
    @memcpy(wrong_bytes[0..wrong_header.len], wrong_header);
    @memcpy(wrong_bytes[wrong_header.len..], "wrong!");
    var valid_header_storage: [16]u8 = undefined;
    const valid_header = try webtransport.BidirectionalStreamHeader.writeInto(
        &valid_header_storage,
        session_id,
    );
    var valid_bytes_storage: [32]u8 = undefined;
    const valid_bytes = valid_bytes_storage[0 .. valid_header.len + "ok".len];
    @memcpy(valid_bytes[0..valid_header.len], valid_header);
    @memcpy(valid_bytes[valid_header.len..], "ok");
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = wrong_bytes,
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = valid_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var out: [8]u8 = undefined;
    try std.testing.expect((try pollOnce(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
    const rejection_code =
        webtransport.ApplicationErrorCode.buffered_stream_rejected;
    try std.testing.expectEqual(
        rejection_code,
        connection.sendStreamStats(4).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        rejection_code,
        connection.recvStreamStats(4).?.stop_sending_sent.?
            .application_error_code,
    );
    var rejection_datagram = try sender.receiveBytes();
    defer rejection_datagram.deinit(allocator);
    var rejection = try quic.one_rtt.openReceivedBytes(
        &sender,
        rejection_datagram.from,
        rejection_datagram.bytes,
        keys,
        "wt-wrong-bidi-client".len,
        0,
        4,
    );
    defer rejection.deinit(allocator);
    var saw_reset = false;
    var saw_stop = false;
    for (rejection.frames) |frame| switch (frame) {
        .reset_stream => |reset_info| {
            try std.testing.expectEqual(@as(u64, 4), reset_info.stream_id);
            try std.testing.expectEqual(
                rejection_code,
                reset_info.application_error_code,
            );
            saw_reset = true;
        },
        .stop_sending => |stop_info| {
            try std.testing.expectEqual(@as(u64, 4), stop_info.stream_id);
            try std.testing.expectEqual(
                rejection_code,
                stop_info.application_error_code,
            );
            saw_stop = true;
        },
        else => {},
    };
    try std.testing.expect(saw_reset);
    try std.testing.expect(saw_stop);
    try std.testing.expectEqual(@as(u64, 0), quic.one_rtt.testing.receiveDataConsumed(&connection));
    try std.testing.expect(registry.get(4) == null);

    // The next bounded turn drains retained bytes and restores connection
    // credit without also publishing an application event.
    try std.testing.expect((try pollOnce(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
    try std.testing.expectEqual(@as(u64, wrong_bytes.len), quic.one_rtt.testing.receiveDataConsumed(&connection));
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );

    const event = (try pollOnce(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 8), event.data.stream_id);
    try std.testing.expectEqualStrings("ok", out[0..event.data.bytes]);
    try std.testing.expect(event.data.fin);
}

/// Abort the local send direction with a mapped WebTransport error code.
pub fn reset(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStream(stream_id, http3_code);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction under one absolute awake-clock deadline.
/// The registry is committed only after RESET_STREAM reaches the socket.
pub fn resetWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStreamWithDeadline(
        stream_id,
        http3_code,
        deadline,
    );
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction once without sleeping for QUIC pacing.
/// Registry state changes only after the RESET_STREAM packet is submitted.
pub fn resetOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.tryResetStream(stream_id, http3_code);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction while guaranteeing delivery of an
/// application-data prefix. `reliable_size` excludes the WebTransport stream
/// association prefix, which must already have reached the QUIC send path.
pub fn resetReliably(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    reliable_size: u64,
) Error!void {
    const prepared = try prepareReliableReset(
        registry,
        stream_id,
        reliable_size,
    );
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStreamReliably(
        stream_id,
        http3_code,
        prepared.wire_reliable_size,
    );
    prepared.stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, prepared.stream);
}

/// Deadline-bounded reliable reset. Registry state changes only after the
/// RESET_STREAM_AT frame reaches the socket.
pub fn resetReliablyWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    reliable_size: u64,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    const prepared = try prepareReliableReset(
        registry,
        stream_id,
        reliable_size,
    );
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStreamReliablyWithDeadline(
        stream_id,
        http3_code,
        prepared.wire_reliable_size,
        deadline,
    );
    prepared.stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, prepared.stream);
}

/// Single-attempt counterpart for shared-endpoint dispatchers.
pub fn resetReliablyOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    reliable_size: u64,
) Error!void {
    const prepared = try prepareReliableReset(
        registry,
        stream_id,
        reliable_size,
    );
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.tryResetStreamReliably(
        stream_id,
        http3_code,
        prepared.wire_reliable_size,
    );
    prepared.stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, prepared.stream);
}

const PreparedReliableReset = struct {
    stream: *webtransport.StreamState,
    wire_reliable_size: u64,
};

fn prepareReliableReset(
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    reliable_size: u64,
) Error!PreparedReliableReset {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if ((stream.direction == .unidirectional and
        !stream.locally_initiated) or
        stream.send_reset != null or
        stream.stopped != null or
        stream.local_fin)
    {
        return error.InvalidStreamState;
    }
    if (!stream.prefix_sent or reliable_size > stream.bytes_sent) {
        return error.InvalidStreamState;
    }
    const prefix_size = stream.send_offset - stream.bytes_sent;
    return .{
        .stream = stream,
        .wire_reliable_size = std.math.add(
            u64,
            prefix_size,
            reliable_size,
        ) catch return error.IntegerOverflow,
    };
}

/// Cancel the peer send direction with a mapped WebTransport error code.
pub fn stop(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.sendStopSending(stream_id, http3_code);
    stream.stop_sent = .fromHttp3(http3_code);
    _ = try connection.discardStoppedReceived(stream_id);
}

/// Cancel the peer send direction under one absolute awake-clock deadline.
/// Registry state changes only after STOP_SENDING reaches the socket, so a
/// timeout can be retried without suppressing the cancellation.
pub fn stopWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.sendStopSendingWithDeadline(
        stream_id,
        http3_code,
        deadline,
    );
    stream.stop_sent = .fromHttp3(http3_code);
    _ = try connection.discardStoppedReceived(stream_id);
}

/// Cancel the peer send direction once without sleeping for QUIC pacing.
/// Registry state changes only after STOP_SENDING reaches the socket.
pub fn stopOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.trySendStopSending(stream_id, http3_code);
    stream.stop_sent = .fromHttp3(http3_code);
}

pub fn poll(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!?Read {
    return pollInternal(connection, registry, session_id, out, false);
}

/// Poll one buffered stream event without waiting for receive-credit pacing.
/// Application bytes are returned only after the matching QUIC receive cursor
/// has committed, so retrying never duplicates a delivered payload.
pub fn pollOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!?Read {
    return pollInternal(connection, registry, session_id, out, true);
}

fn pollInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    single_attempt: bool,
) Error!?Read {
    const drained = try association.drainAbandonedReceives(
        connection,
        registry,
        single_attempt,
    );
    if (single_attempt and drained) return null;
    if (try pollKnownStopped(connection, registry)) |event| return event;
    if (try pollKnownReset(connection, registry, null)) |event| return event;

    var stream_ids: [256]u62 = undefined;
    const previous = registry.incremental_poll_cursor;
    var after = previous;
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(after, &stream_ids);
        for (ids) |stream_id| {
            var transport_progressed = false;
            if (try pollStreamId(
                connection,
                registry,
                session_id,
                stream_id,
                out,
                single_attempt,
                &transport_progressed,
            )) |event| return event;
            if (single_attempt and transport_progressed) return null;
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) break;
    }
    if (previous == null) return null;

    // Wrap to the lowest active ID. The cursor is an ID rather than a physical
    // table slot, so reclaiming its stream between calls cannot skip a moved
    // entry.
    after = null;
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(after, &stream_ids);
        for (ids) |stream_id| {
            if (stream_id > previous.?) return null;
            var transport_progressed = false;
            if (try pollStreamId(
                connection,
                registry,
                session_id,
                stream_id,
                out,
                single_attempt,
                &transport_progressed,
            )) |event| return event;
            if (single_attempt and transport_progressed) return null;
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) return null;
    }
}

fn pollStreamId(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
    single_attempt: bool,
    transport_progressed: *bool,
) Error!?Read {
    // Association-prefix parsing, rather than numeric guesses, distinguishes
    // HTTP/3 critical/push streams from WebTransport.
    if (stream_id == session_id.value) return null;
    const event = try pollStream(
        connection,
        registry,
        session_id,
        stream_id,
        out,
        single_attempt,
        transport_progressed,
    ) orelse return null;
    registry.incremental_poll_cursor = switch (event) {
        inline else => |value| value.stream_id,
    };
    return event;
}

fn pollStream(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
    single_attempt: bool,
    transport_progressed: *bool,
) Error!?Read {
    // A session can mix whole-stream and incremental consumption as long as a
    // single receive direction never changes mode. Skip streams claimed by
    // the whole-stream reader so an already-consumed stream cannot prevent
    // incremental events from other associated streams being observed.
    if (registry.get(stream_id)) |registered| {
        if (registered.receive_mode == .whole) return null;
    }
    const identification = (if (single_attempt)
        association.identifyClassifiedOnce(
            connection,
            registry,
            session_id,
            stream_id,
            .incremental,
        )
    else
        association.identifyClassified(
            connection,
            registry,
            session_id,
            stream_id,
            .incremental,
        )) catch |err| switch (err) {
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        => return null,
        else => return err,
    };
    const stream = switch (identification) {
        .associated => |value| value,
        .rejected => |progressed| {
            transport_progressed.* = progressed;
            return null;
        },
        .unclaimed => return null,
    };

    if (connection.sendStreamStats(stream_id)) |stats| {
        if (stats.reset) |reset_info| {
            stream.send_reset =
                .fromHttp3(reset_info.application_error_code);
        }
        if (stats.stopped) |stopped| {
            if (stream.stopped == null) {
                stream.stopped =
                    .fromHttp3(stopped.application_error_code);
            }
            if (!stream.stopped_reported) {
                stream.stopped_reported = true;
                return stoppedEvent(stream, stream_id);
            }
        }
    }
    if (try pollKnownReset(connection, registry, stream_id)) |event| {
        return event;
    }

    const recv_stats = connection.recvStreamStats(stream_id) orelse
        return null;
    if (recv_stats.reset) |reset_info| {
        if (reset_info.reliable_size == 0 or
            recv_stats.bytes_read >= reset_info.reliable_size)
        {
            if (stream.receive_reset == null) {
                stream.receive_reset =
                    .fromHttp3(reset_info.application_error_code);
                stream.receive_reset_final_size = reset_info.final_size;
            }
            if (!stream.reset_reported) {
                // Ordinary RESET_STREAM hides retained bytes immediately.
                // RESET_STREAM_AT reaches this branch only after its reliable
                // prefix has passed through the application read path.
                _ = try connection.discardResetReceived(stream_id);
                _ = try association.requestTransportRetirement(connection, stream);
                stream.reset_reported = true;
                return resetEvent(stream, stream_id, reset_info.final_size);
            }
            return null;
        }
    }
    // The shared pre-poll sweep has already discarded any locally stopped
    // receive direction, including when this call targets a sibling stream.
    if (stream.stop_sent != null) return null;

    const available = connection.availableReceivedStream(stream_id) orelse
        return null;
    if (available.len != 0) {
        const count = @min(out.len, available.len);
        @memcpy(out[0..count], available[0..count]);
        const fin = recv_stats.reset == null and
            recv_stats.final_size != null and
            recv_stats.bytes_read + count == recv_stats.final_size.?;
        const previous_stream = stream.*;
        try registry.recordReceived(stream_id, count, fin);
        const release_result = if (single_attempt)
            connection.tryReleaseReceivedCapacity(stream_id, count)
        else
            connection.releaseReceivedCapacity(stream_id, count);
        release_result catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {
                stream.* = previous_stream;
                return null;
            },
            else => {
                stream.* = previous_stream;
                return err;
            },
        };
        if (fin) {
            _ = association.requestTransportRetirement(
                connection,
                stream,
            ) catch unreachable;
        }
        return dataEvent(stream, stream_id, count, fin);
    }
    if (recv_stats.final_size != null and
        recv_stats.bytes_read == recv_stats.final_size.? and
        !stream.peer_fin)
    {
        _ = try association.requestTransportRetirement(connection, stream);
        try registry.recordReceived(stream_id, 0, true);
        return dataEvent(stream, stream_id, 0, true);
    }
    return null;
}

fn pollKnownStopped(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!?Read {
    for (registry.registered()) |*stream| {
        const stats = connection.sendStreamStats(stream.stream_id) orelse
            continue;
        if (stats.reset) |reset_info| {
            stream.send_reset =
                .fromHttp3(reset_info.application_error_code);
        }
        const stopped = stats.stopped orelse continue;
        if (stream.stopped == null) {
            stream.stopped = .fromHttp3(stopped.application_error_code);
        }
        if (stream.stopped_reported) continue;
        try association.requestAfterSendTerminal(connection, stream);
        stream.stopped_reported = true;
        return stoppedEvent(stream, stream.stream_id);
    }
    return null;
}

fn pollKnownReset(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    target_stream_id: ?u62,
) Error!?Read {
    for (registry.registered()) |*stream| {
        if (target_stream_id) |target| {
            if (stream.stream_id != target) continue;
        }
        if (stream.receive_mode == .whole or stream.reset_reported or
            stream.receive_reset == null or
            stream.receive_reset_final_size == null)
        {
            continue;
        }
        if (stream.receive_mode == .unset) {
            stream.receive_mode = .incremental;
        }
        try association.requestAfterSendTerminal(connection, stream);
        stream.reset_reported = true;
        return resetEvent(
            stream,
            stream.stream_id,
            stream.receive_reset_final_size.?,
        );
    }
    return null;
}

fn dataEvent(
    stream: *const webtransport.StreamState,
    stream_id: u62,
    bytes: usize,
    fin: bool,
) Read {
    return .{ .data = .{
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .bytes = bytes,
        .fin = fin,
    } };
}

fn resetEvent(
    stream: *const webtransport.StreamState,
    stream_id: u62,
    final_size: u64,
) Read {
    return .{ .reset = .{
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .error_info = stream.receive_reset.?,
        .final_size = final_size,
    } };
}

fn stoppedEvent(
    stream: *const webtransport.StreamState,
    stream_id: u62,
) Read {
    return .{ .stopped = .{
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .error_info = stream.stopped.?,
    } };
}

test "WebTransport incremental read consumes one UDP GRO stream batch" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gro_receive = true },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x69} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 1 },
    );
    defer registry.deinit();

    const first_data = [_]u8{ 0x40, 0x41, 0x00 } ++
        [_]u8{0xa5} ** 999;
    const second_data = [_]u8{0x5a} ** 1000;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .data = &first_data,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = first_data.len,
        .data = &second_data,
        .fin = true,
    } }};
    var out: [2048]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        readWithDeadline(
            &connection,
            &registry,
            session_id,
            &out,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromNanoseconds(0),
            }),
        ),
    );
    try quic.one_rtt.sendFramesBatch(
        &sender,
        receiver.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &.{ &first, &second },
        },
    );

    const event = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 4), event.data.stream_id);
    try std.testing.expectEqual(@as(usize, 1999), event.data.bytes);
    try std.testing.expect(event.data.fin);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** 999),
        out[0..999],
    );
    try std.testing.expectEqualSlices(
        u8,
        &second_data,
        out[999..1999],
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        connection.stats().packets_received,
    );
}

test "WebTransport UDP GRO batch preserves incremental stream rotation" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gro_receive = true },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer sender.deinit();
    if (!receiver.groReceiveEnabled() or !sender.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x79} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    const first_data = [_]u8{ 0x40, 0x41, 0x00 } ++
        [_]u8{0xa1} ** 997;
    const second_data = [_]u8{ 0x40, 0x41, 0x00 } ++
        [_]u8{0xb2} ** 997;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = &first_data,
        .fin = true,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 8,
        .data = &second_data,
        .fin = true,
    } }};
    try quic.one_rtt.sendFramesBatch(
        &sender,
        receiver.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &.{ &first, &second },
        },
    );

    var out: [1024]u8 = undefined;
    const first_event = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(first_event == .data);
    try std.testing.expectEqual(@as(u62, 4), first_event.data.stream_id);
    try std.testing.expectEqual(@as(usize, 997), first_event.data.bytes);
    try std.testing.expect(first_event.data.fin);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa1} ** 997),
        out[0..997],
    );

    // Stream 8 was applied by the same kernel receive. The cursor still
    // returns one stream event per call and advances past stream 4.
    const second_event = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(second_event == .data);
    try std.testing.expectEqual(@as(u62, 8), second_event.data.stream_id);
    try std.testing.expectEqual(@as(usize, 997), second_event.data.bytes);
    try std.testing.expect(second_event.data.fin);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xb2} ** 997),
        out[0..997],
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        connection.stats().packets_received,
    );
}

test "WebTransport incremental polling rotates across busy streams" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-fair-server",
        .peer_connection_id = "wt-fair-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 3 },
    );
    defer registry.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &encoded,
        allocator,
        session_id,
    );
    try encoded.appendSlice(allocator, "busy");
    var idle: std.ArrayList(u8) = .empty;
    defer idle.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &idle,
        allocator,
        session_id,
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            // An unrelated HTTP/3 unidirectional stream and an associated but
            // idle stream must not interfere with the ready-stream rotation.
            .{ .stream = .{ .stream_id = 2, .data = &.{0} } },
            .{ .stream = .{ .stream_id = 4, .data = encoded.items } },
            .{ .stream = .{ .stream_id = 12, .data = idle.items } },
            .{ .stream = .{ .stream_id = 8, .data = encoded.items } },
        },
        null,
        .not_ect,
    );

    var byte: [1]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 4), first.data.stream_id);
    try std.testing.expectEqualStrings("b", &byte);

    // Stream four still has immediately readable bytes, but the stable cursor
    // gives its equally busy sibling the next application scheduling turn.
    const second = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(u62, 8), second.data.stream_id);
    try std.testing.expectEqualStrings("b", &byte);

    const wrapped = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(wrapped == .data);
    try std.testing.expectEqual(@as(u62, 4), wrapped.data.stream_id);
    try std.testing.expectEqualStrings("u", &byte);
}

test "WebTransport stopped receive drains connection credit only" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x92} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-stop-server",
        .peer_connection_id = "wt-stop-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
        .initial_receive_max_streams_bidi = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var first_bytes: [16]u8 = undefined;
    @memcpy(first_bytes[0..prefix.len], prefix);
    @memset(first_bytes[prefix.len..], 0xa5);
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = &first_bytes,
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    var out: [1]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try stop(&connection, &registry, 4, 17);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);

    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );
    try std.testing.expectEqual(
        @as(u64, 16),
        connection.recvStreamStats(4).?.receive_limit,
    );
    try std.testing.expect(registry.get(4).?.peer_fin);
    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "wt-stop-client".len,
        0,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 32),
        credit.frames[0].max_data.maximum_data,
    );
}

test "WebTransport targeted read drains stopped sibling" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x96} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-target-server",
        .peer_connection_id = "wt-target-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 3 },
    );
    defer registry.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var cancelled_start: [17]u8 = undefined;
    @memcpy(cancelled_start[0..prefix.len], prefix);
    cancelled_start[prefix.len] = 'a';
    const cancelled_start_len = prefix.len + 1;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = cancelled_start[0..cancelled_start_len],
        } }},
        null,
        .not_ect,
    );
    var out: [8]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqualStrings("a", out[0..first.data.bytes]);
    try stop(&connection, &registry, 4, 21);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);

    var target_bytes: [18]u8 = undefined;
    @memcpy(target_bytes[0..prefix.len], prefix);
    @memcpy(target_bytes[prefix.len..][0..2], "ok");
    const target_len = prefix.len + 2;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .offset = cancelled_start_len,
                .data = "late",
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = target_bytes[0..target_len],
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    const target = try readId(
        &connection,
        &registry,
        session_id,
        8,
        &out,
    );
    try std.testing.expect(target == .data);
    try std.testing.expectEqual(@as(u62, 8), target.data.stream_id);
    try std.testing.expectEqualStrings("ok", out[0..target.data.bytes]);
    try std.testing.expect(target.data.fin);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );
    try std.testing.expectEqual(
        @as(u64, 16),
        connection.recvStreamStats(4).?.receive_limit,
    );
    try std.testing.expect(registry.get(4).?.peer_fin);
}

test "WebTransport reliable reset maps application bytes to QUIC offsets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xde} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reliable-client",
        .peer_connection_id = "wt-reliable-server",
        .reliable_reset = .{ .peer = true },
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try std.testing.expectError(
        error.InvalidStreamState,
        resetReliably(&connection, &registry, stream.stream_id, 42, 0),
    );
    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    try connection.send(&.{
        .{ .stream = .{
            .stream_id = stream.stream_id,
            .data = prefix,
        } },
        .{ .stream = .{
            .stream_id = stream.stream_id,
            .offset = @intCast(prefix.len),
            .data = "payload",
        } },
    });
    stream.send_offset = prefix.len + "payload".len;
    stream.bytes_sent = "payload".len;
    stream.prefix_sent = true;
    try std.testing.expectError(
        error.InvalidStreamState,
        resetReliably(&connection, &registry, stream.stream_id, 42, 8),
    );

    const association_prefix_size = stream.send_offset - stream.bytes_sent;
    try resetReliably(&connection, &registry, stream.stream_id, 42, 4);
    const reset_info = connection.sendStreamStats(stream.stream_id).?.reset.?;
    try std.testing.expectEqual(
        association_prefix_size + 4,
        reset_info.reliable_size,
    );
    try std.testing.expectEqual(
        @as(?u32, 42),
        stream.send_reset.?.application_code,
    );
}

test "WebTransport reset event restores final-size connection credit" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reset-server",
        .peer_connection_id = "wt-reset-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &storage,
        session_id,
    );
    var initial: [17]u8 = undefined;
    @memcpy(initial[0..prefix.len], prefix);
    initial[prefix.len] = 'x';
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = initial[0 .. prefix.len + 1],
            } },
            .{ .reset_stream = .{
                .stream_id = 4,
                .application_error_code = webtransport.applicationErrorCodeToHttp3(24),
                .final_size = 8,
            } },
        },
        null,
        .not_ect,
    );
    var out: [8]u8 = undefined;
    const event = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(@as(u62, 4), event.reset.stream_id);
    try std.testing.expectEqual(
        @as(?u32, 24),
        event.reset.error_info.application_code,
    );
    try std.testing.expectEqual(@as(u64, 8), event.reset.final_size);
    try std.testing.expectEqual(
        @as(u64, 8),
        connection.recvStreamStats(4).?.receive_limit,
    );

    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "wt-reset-client".len,
        0,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 16),
        credit.frames[0].max_data.maximum_data,
    );
}

test "WebTransport reliable reset delivers its prefix before reset" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reliable-server",
        .peer_connection_id = "wt-reliable-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 32,
        .initial_receive_max_stream_data = 32,
        .initial_receive_max_streams_bidi = 2,
        .reliable_reset = .{ .local = true },
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var first_bytes: [18]u8 = undefined;
    @memcpy(first_bytes[0..prefix.len], prefix);
    @memcpy(first_bytes[prefix.len..][0..2], "ab");
    const first_len = prefix.len + 2;
    const reliable_size: u64 = @intCast(prefix.len + 4);
    const final_size: u64 = @intCast(prefix.len + 6);
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = first_bytes[0..first_len],
            } },
            .{ .reset_stream_at = .{
                .stream_id = 4,
                .application_error_code = webtransport.applicationErrorCodeToHttp3(25),
                .final_size = final_size,
                .reliable_size = reliable_size,
            } },
        },
        null,
        .not_ect,
    );

    var out: [8]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqualStrings("ab", out[0..first.data.bytes]);
    try std.testing.expect(!first.data.fin);
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 4,
            .offset = @intCast(first_len),
            .data = "cdxx",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    const second = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second == .data);
    try std.testing.expectEqualStrings("cd", out[0..second.data.bytes]);
    try std.testing.expect(!second.data.fin);

    const reset_event = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(reset_event == .reset);
    try std.testing.expectEqual(@as(u62, 4), reset_event.reset.stream_id);
    try std.testing.expectEqual(
        @as(?u32, 25),
        reset_event.reset.error_info.application_code,
    );
    try std.testing.expectEqual(final_size, reset_event.reset.final_size);
}

test "WebTransport targeted sibling preserves reset after transport reclaim" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x98} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reclaim-local",
        .peer_connection_id = "wt-reclaim-peer",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
        .initial_receive_max_streams_bidi = 2,
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2, .max_peer_uni = 1 },
    );
    defer registry.deinit();

    var reset_bytes: std.ArrayList(u8) = .empty;
    defer reset_bytes.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &reset_bytes,
        allocator,
        session_id,
    );
    try reset_bytes.append(allocator, 'x');
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 2,
            .data = reset_bytes.items,
        } }},
        null,
        .not_ect,
    );
    var out: [8]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 2), first.data.stream_id);
    try std.testing.expectEqualStrings("x", out[0..first.data.bytes]);

    var target_storage: [16]u8 = undefined;
    const target_prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &target_storage,
        session_id,
    );
    var target_bytes: [18]u8 = undefined;
    @memcpy(target_bytes[0..target_prefix.len], target_prefix);
    @memcpy(target_bytes[target_prefix.len..][0..2], "ok");
    const reset_final_size: u64 = 8;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .reset_stream = .{
                .stream_id = 2,
                .application_error_code = webtransport.applicationErrorCodeToHttp3(25),
                .final_size = reset_final_size,
            } },
            .{ .stream = .{
                .stream_id = 4,
                .data = target_bytes[0 .. target_prefix.len + 2],
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    const target = try readId(
        &connection,
        &registry,
        session_id,
        4,
        &out,
    );
    try std.testing.expect(target == .data);
    try std.testing.expectEqualStrings("ok", out[0..target.data.bytes]);
    try std.testing.expect(target.data.fin);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(connection.recvStreamStats(2) == null);

    const reset_event = (try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(reset_event == .reset);
    try std.testing.expectEqual(@as(u62, 2), reset_event.reset.stream_id);
    try std.testing.expectEqual(
        @as(?u32, 25),
        reset_event.reset.error_info.application_code,
    );
    try std.testing.expectEqual(
        reset_final_size,
        reset_event.reset.final_size,
    );
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) == null);
}

test "WebTransport incremental deadlines preserve buffered stream events" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-deadline-server",
        .peer_connection_id = "wt-deadline-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var encoded: [21]u8 = undefined;
    @memcpy(encoded[0..prefix.len], prefix);
    @memcpy(encoded[prefix.len..][0..5], "ready");
    const stream_bytes = encoded[0 .. prefix.len + 5];
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .data = stream_bytes,
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = stream_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var out = [_]u8{0xa5} ** 5;
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(4).?.bytes_read,
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expectError(
        error.Timeout,
        readWithDeadline(
            &connection,
            &registry,
            session_id,
            &out,
            .fromNow(io, .{
                .clock = .real,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 5), &out);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(4).?.bytes_read,
    );
    try std.testing.expect(registry.get(4) == null);

    const first = try readWithDeadline(
        &connection,
        &registry,
        session_id,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 4), first.data.stream_id);
    try std.testing.expectEqualStrings("ready", &out);
    try std.testing.expect(first.data.fin);

    @memset(&out, 0xa5);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(8).?.bytes_read,
    );
    try std.testing.expect(registry.get(8) == null);
    try std.testing.expectError(
        error.Timeout,
        readIdWithDeadline(
            &connection,
            &registry,
            session_id,
            8,
            &out,
            .fromNow(io, .{
                .clock = .real,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 5), &out);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(8).?.bytes_read,
    );
    try std.testing.expect(registry.get(8) == null);

    const second = try readIdWithDeadline(
        &connection,
        &registry,
        session_id,
        8,
        &out,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(u62, 8), second.data.stream_id);
    try std.testing.expectEqualStrings("ready", &out);
    try std.testing.expect(second.data.fin);
}

//! Incremental caller-buffer WebTransport stream reads and cancellation.

const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const association = @import("stream_association.zig");

pub const Error = association.Error;

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
/// retention. The supplied buffer must be non-empty.
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

        var packet = try connection.receivePacketServicingTimers();
        defer packet.deinit(connection.endpoint.allocator);
        _ = connection.sendAckForPacketsIfNeeded(
            @as(*const [1]quic.one_rtt.ReceivedPacket, &packet),
        ) catch {};
    }
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
}

fn poll(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!?Read {
    if (pollKnownStopped(connection, registry)) |event| return event;

    var stream_ids: [256]u62 = undefined;
    var start: usize = 0;
    while (true) {
        const ids = connection.receivedStreamIdsFromInto(
            start,
            &stream_ids,
        );
        for (ids) |stream_id| {
            if (stream_id == session_id.value or
                isHttp3CriticalOrPushStream(stream_id))
            {
                continue;
            }
            if (try pollStream(
                connection,
                registry,
                session_id,
                stream_id,
                out,
            )) |event| return event;
        }
        start += ids.len;
        if (ids.len < stream_ids.len) return null;
    }
}

fn pollStream(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
) Error!?Read {
    const stream = try association.identify(
        connection,
        registry,
        session_id,
        stream_id,
        .incremental,
    ) orelse return null;

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

    const recv_stats = connection.recvStreamStats(stream_id) orelse
        return null;
    if (recv_stats.reset) |reset_info| {
        if (stream.receive_reset == null) {
            stream.receive_reset =
                .fromHttp3(reset_info.application_error_code);
        }
        if (!stream.reset_reported) {
            // RESET_STREAM terminates the receive direction at packet
            // application time. It can overtake earlier STREAM packets, so
            // retained or later-arriving bytes are never exposed after reset.
            stream.reset_reported = true;
            return resetEvent(stream, stream_id, reset_info.final_size);
        }
        return null;
    }
    if (stream.stop_sent != null) {
        // Bytes already in flight remain bounded in QUIC but are not delivered
        // after the application has cancelled this receive direction.
        return null;
    }

    const available = connection.availableReceivedStream(stream_id) orelse
        return null;
    if (available.len != 0) {
        const count = @min(out.len, available.len);
        @memcpy(out[0..count], available[0..count]);
        try connection.releaseReceivedCapacity(stream_id, count);
        const after = connection.recvStreamStats(stream_id).?;
        const fin = after.reset == null and
            after.final_size != null and
            after.bytes_read == after.final_size.?;
        try registry.recordReceived(stream_id, count, fin);
        return dataEvent(stream, stream_id, count, fin);
    }
    if (recv_stats.final_size != null and
        recv_stats.bytes_read == recv_stats.final_size.? and
        !stream.peer_fin)
    {
        try registry.recordReceived(stream_id, 0, true);
        return dataEvent(stream, stream_id, 0, true);
    }
    return null;
}

fn pollKnownStopped(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) ?Read {
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
        stream.stopped_reported = true;
        return stoppedEvent(stream, stream.stream_id);
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

fn isHttp3CriticalOrPushStream(stream_id: u62) bool {
    return switch (stream_id) {
        2, 3, 6, 7, 10, 11 => true,
        else => false,
    };
}

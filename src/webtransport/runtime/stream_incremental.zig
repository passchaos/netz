//! Incremental caller-buffer WebTransport stream reads and cancellation.

const std = @import("std");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const association = @import("stream_association.zig");
const connection_lifecycle = @import("connection_lifecycle.zig");
const flow_receive = @import("flow/receive.zig");
const flow_progress = @import("flow/progress.zig");
const receive_credit = @import("stream/receive_credit.zig");
const stream_read_buffer = @import("stream/read_buffer.zig");

test {
    _ = @import("stream/receive_credit_tests.zig");
    _ = @import("stream/read_buffer_tests.zig");
    _ = @import("stream/read_target_tests.zig");
    _ = @import("stream/closed_extension_tests.zig");
}

pub const Error = association.Error || @import("session_control.zig").Error;
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
    return readWithProgress(connection, registry, session_id, null, out, null, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

/// Relative-timeout counterpart to `read`. A non-positive duration returns
/// `Timeout` before any socket wait or stream bookkeeping.
pub fn readWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    timeout: std.Io.Duration,
) (Error || quic.runtime.ReceiveTimeoutError)!Read {
    return readWithProgress(
        connection,
        registry,
        session_id,
        null,
        out,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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
    return readWithProgress(connection, registry, session_id, null, out, deadline, null);
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
    return readWithProgress(connection, registry, session_id, stream_id, out, null, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

/// Relative-timeout counterpart to `readId`. A non-positive duration returns
/// `Timeout` before any socket wait or stream bookkeeping.
pub fn readIdWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
    timeout: std.Io.Duration,
) (Error || quic.runtime.ReceiveTimeoutError)!Read {
    return readWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        out,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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
    return readWithProgress(connection, registry, session_id, stream_id, out, deadline, null);
}

/// Owning-session read with maintenance before each buffered poll or socket
/// wait. A nullable target preserves sibling state for stream-ID readers.
pub fn readWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    target: ?u62,
    out: []u8,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!Read {
    try stream_read_buffer.validate(out);
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        if (progress) |owner| try owner.maintain(deadline);
        if (target) |stream_id| {
            _ = try association.drainAbandonedReceives(connection, registry, false);
            var advanced = false;
            if (try pollStream(connection, registry, session_id, stream_id, out, false, &advanced, null)) |event| return event;
        } else {
            if (try poll(connection, registry, session_id, out)) |event| return event;
        }
        if (progress) |owner| {
            if (try owner.receive(deadline)) continue;
        }
        if (deadline) |absolute|
            try serviceReceiveWithDeadline(connection, absolute)
        else
            try serviceReceive(connection);
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

const stream_reset = @import("stream/reset.zig");
pub const reset = stream_reset.reset;
pub const resetWithTimeout = stream_reset.resetWithTimeout;
pub const resetWithDeadline = stream_reset.resetWithDeadline;
pub const resetOnce = stream_reset.resetOnce;
pub const resetReliably = stream_reset.resetReliably;
pub const resetReliablyWithTimeout = stream_reset.resetReliablyWithTimeout;
pub const resetReliablyWithDeadline = stream_reset.resetReliablyWithDeadline;
pub const resetReliablyOnce = stream_reset.resetReliablyOnce;

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

/// Relative-timeout counterpart to `stop`. A non-positive duration returns
/// `Timeout` before registry lookup or any STOP_SENDING write.
pub fn stopWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    timeout: std.Io.Duration,
) TimeoutError!void {
    return stopWithDeadline(
        connection,
        registry,
        stream_id,
        application_error_code,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
    );
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
    return pollInternal(connection, registry, session_id, out, false, null);
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
    return pollInternal(connection, registry, session_id, out, true, null);
}

/// Shared-endpoint counterpart that preserves streams associated with another
/// accepted Session instead of rejecting them as unknown to this registry.
pub fn pollOnceShared(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    sessions: association.SessionLookup,
) Error!?Read {
    return pollInternal(
        connection,
        registry,
        session_id,
        out,
        true,
        sessions,
    );
}

fn pollInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    single_attempt: bool,
    sessions: ?association.SessionLookup,
) Error!?Read {
    try stream_read_buffer.validate(out);
    if (connection_lifecycle.terminating(connection)) return error.ConnectionClosed;
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
                sessions,
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
                sessions,
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
    sessions: ?association.SessionLookup,
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
        sessions,
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
    sessions: ?association.SessionLookup,
) Error!?Read {
    if (connection_lifecycle.terminating(connection)) return error.ConnectionClosed;
    // A session can mix whole-stream and incremental consumption as long as a
    // single receive direction never changes mode. Skip streams claimed by
    // the whole-stream reader so an already-consumed stream cannot prevent
    // incremental events from other associated streams being observed.
    const known_stream = registry.get(stream_id);
    if (known_stream) |registered| {
        // Send-side control is independent of receive mode. A targeted read
        // must still observe STOP when whole-stream data has another owner.
        if (try pollStoppedStream(connection, registered)) |event| return event;
        if (registered.receive_mode == .whole) return null;
    }
    const identification = (if (single_attempt)
        if (sessions) |known|
            association.identifyClassifiedOnceShared(
                connection,
                registry,
                session_id,
                stream_id,
                .incremental,
                known,
            )
        else
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

    if (known_stream == null) {
        if (try pollStoppedStream(connection, stream)) |event| return event;
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
                flow_receive.consumeAbandoned(registry, stream);
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
        receive_credit.commit(connection, stream_id, count) catch |err| {
            stream.* = previous_stream;
            return err;
        };
        flow_receive.consume(registry, stream, count);
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

fn pollStoppedStream(connection: *quic.one_rtt.Connection, stream: *webtransport.StreamState) Error!?Read {
    if (connection.sendStreamStats(stream.stream_id)) |stats| {
        if (stats.reset) |reset_info| stream.send_reset = .fromHttp3(reset_info.application_error_code);
        if (stats.stopped) |stopped| {
            if (stream.stopped == null) stream.stopped = .fromHttp3(stopped.application_error_code);
        }
    }
    if (stream.stopped == null or stream.stopped_reported) return null;
    try association.requestAfterSendTerminal(connection, stream);
    stream.stopped_reported = true;
    return stoppedEvent(stream, stream.stream_id);
}

fn pollKnownStopped(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!?Read {
    for (registry.registered()) |*stream| {
        if (try pollStoppedStream(connection, stream)) |event| return event;
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

test {
    _ = @import("stream_incremental/tests.zig");
}
